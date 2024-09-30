use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use dashmap::DashMap;
use regex::Regex;
use std::collections::HashMap;
use std::collections::BTreeSet;

use crate::LogFormat;
use crate::LogFormat::Linux;
use crate::LogFormat::OpenStack;
use crate::LogFormat::Spark;
use crate::LogFormat::HDFS;
use crate::LogFormat::HPC;
use crate::LogFormat::Proxifier;
use crate::LogFormat::Android;
use crate::LogFormat::HealthApp;

pub fn format_string(lf: &LogFormat) -> String {
    match lf {
        Linux =>
            r"<Month> <Date> <Time> <Level> <Component>(\\[<PID>\\])?: <Content>".to_string(),
        OpenStack =>
            r"'<Logrecord> <Date> <Time> <Pid> <Level> <Component> \[<ADDR>\] <Content>'".to_string(),
        Spark =>
            r"<Date> <Time> <Level> <Component>: <Content>".to_string(),
        HDFS =>
            r"<Date> <Time> <Pid> <Level> <Component>: <Content>".to_string(),
        HPC =>
            r"<LogId> <Node> <Component> <State> <Time> <Flag> <Content>".to_string(),
        Proxifier =>
            r"[<Time>] <Program> - <Content>".to_string(),
        Android =>
            r"<Date> <Time>  <Pid>  <Tid> <Level> <Component>: <Content>".to_string(),
        HealthApp =>
            "<Time>\\|<Component>\\|<Pid>\\|<Content>".to_string()
    }
}

pub fn censored_regexps(lf: &LogFormat) -> Vec<Regex> {
    match lf {
        Linux =>
            vec![Regex::new(r"(\d+\.){3}\d+").unwrap(),
                 Regex::new(r"\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4}").unwrap(),
                 Regex::new(r"\d{2}:\d{2}:\d{2}").unwrap()],
        OpenStack =>
            vec![Regex::new(r"((\d+\.){3}\d+,?)+").unwrap(),
                 Regex::new(r"/.+?\s").unwrap()],
        // I commented out Regex::new(r"\d+").unwrap() because that censors all numbers, which may not be what we want?
        Spark =>
            vec![Regex::new(r"(\d+\.){3}\d+").unwrap(),
                 Regex::new(r"\b[KGTM]?B\b").unwrap(), 
                 Regex::new(r"([\w-]+\.){2,}[\w-]+").unwrap()],
        HDFS =>
            vec![Regex::new(r"blk_(|-)[0-9]+").unwrap(), // block id
                Regex::new(r"(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)").unwrap() // IP
                ],
        // oops, numbers require lookbehind, which rust doesn't support, sigh
        //                Regex::new(r"(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$").unwrap()]; // Numbers
        HPC =>
            vec![Regex::new(r"=\d+").unwrap()],
        Proxifier =>
            vec![Regex::new(r"<\d+\ssec").unwrap(),
                 Regex::new(r"([\w-]+\.)+[\w-]+(:\d+)?").unwrap(),
                 Regex::new(r"\d{2}:\d{2}(:\d{2})*").unwrap(),
                 Regex::new(r"[KGTM]B").unwrap()],
        Android =>
            vec![Regex::new(r"(/[\w-]+)+").unwrap(),
                 Regex::new(r"([\w-]+\.){2,}[\w-]+").unwrap(),
                 Regex::new(r"\b(\-?\+?\d+)\b|\b0[Xx][a-fA-F\d]+\b|\b[a-fA-F\d]{4,}\b").unwrap()],
        HealthApp => vec![],
    }
}

// https://doc.rust-lang.org/rust-by-example/std_misc/file/read_lines.html
// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn regex_generator_helper(format: String) -> String {
    let splitters_re = Regex::new(r"(<[^<>]+>)").unwrap();
    let spaces_re = Regex::new(r" +").unwrap();
    let brackets : &[_] = &['<', '>'];

    let mut r = String::new();
    let mut prev_end = None;
    for m in splitters_re.find_iter(&format) {
        if let Some(pe) = prev_end {
            let splitter = spaces_re.replace(&format[pe..m.start()], r"\s+");
            r.push_str(&splitter);
        }
        let header = m.as_str().trim_matches(brackets).to_string();
        r.push_str(format!("(?P<{}>.*?)", header).as_str());
        prev_end = Some(m.end());
    }
    return r;
}

pub fn regex_generator(format: String) -> Regex {
    return Regex::new(format!("^{}$", regex_generator_helper(format)).as_str()).unwrap();
}

#[test]
fn test_regex_generator_helper() {
    let linux_format = r"<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>".to_string();
    assert_eq!(regex_generator_helper(linux_format), r"(?P<Month>.*?)\s+(?P<Date>.*?)\s+(?P<Time>.*?)\s+(?P<Level>.*?)\s+(?P<Component>.*?)(\[(?P<PID>.*?)\])?:\s+(?P<Content>.*?)");

    let openstack_format = r"<Logrecord> <Date> <Time> <Pid> <Level> <Component> (\[<ADDR>\])? <Content>".to_string();
    assert_eq!(regex_generator_helper(openstack_format), r"(?P<Logrecord>.*?)\s+(?P<Date>.*?)\s+(?P<Time>.*?)\s+(?P<Pid>.*?)\s+(?P<Level>.*?)\s+(?P<Component>.*?)\s+(\[(?P<ADDR>.*?)\])?\s+(?P<Content>.*?)");
}

/// Replaces provided (domain-specific) regexps with <*> in the log_line.
fn apply_domain_specific_re(log_line: String, domain_specific_re:&Vec<Regex>) -> String {
    let mut line = format!(" {}", log_line);
    for s in domain_specific_re {
        line = s.replace_all(&line, "<*>").to_string();
    }
    return line;
}

#[test]
fn test_apply_domain_specific_re() {
    let line = "q2.34.4.5 Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; Fri Jun 17 20:55:07 2005 user unknown".to_string();
    let censored_line = apply_domain_specific_re(line, &censored_regexps(&Linux));
    assert_eq!(censored_line, " q<*> Jun 14 <*> combo sshd(pam_unix)[19937]: check pass; <*> user unknown");
}

pub fn token_splitter(log_line: String, re:&Regex, domain_specific_re:&Vec<Regex>) -> Vec<String> {
    if let Some(m) = re.captures(log_line.trim()) {
        let message = m.name("Content").unwrap().as_str().to_string();
        // println!("{}", &message);
        let line = apply_domain_specific_re(message, domain_specific_re);
        return line.trim().split_whitespace().map(|s| s.to_string()).collect();
    } else {
        return vec![];
    }
}

#[test]
fn test_token_splitter() {
    let line = "Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; user unknown".to_string();
    let re = regex_generator(format_string(&Linux));
    let split_line = token_splitter(line, &re, &censored_regexps(&Linux));
    assert_eq!(split_line, vec!["check", "pass;", "user", "unknown"]);
}

// processes line, adding to the end of line the first two tokens from lookahead_line, and returns the first 2 tokens on this line
fn process_dictionary_builder_line(line: String, lookahead_line: Option<String>, regexp:&Regex, regexps:&Vec<Regex>, dbl: &mut HashMap<String, i32>, trpl: &mut HashMap<String, i32>, all_token_list: &mut Vec<String>, prev1: Option<String>, prev2: Option<String>) -> (Option<String>, Option<String>) {
    let (next1, next2) = match lookahead_line {
        None => (None, None),
        Some(ll) => {
            let next_tokens = token_splitter(ll, &regexp, &regexps);
            match next_tokens.len() {
                0 => (None, None),
                1 => (Some(next_tokens[0].clone()), None),
                _ => (Some(next_tokens[0].clone()), Some(next_tokens[1].clone()))
            }
        }
    };

    // log message is split into tokens
    let mut tokens = token_splitter(line, &regexp, &regexps);
    if tokens.is_empty() {
        return (None, None);
    }
    tokens.iter().for_each(|t| if !all_token_list.contains(t) { all_token_list.push(t.clone()) } );

    // keep this for later when we'll return it
    let last1 = match tokens.len() {
        0 => None,
        n => Some(tokens[n-1].clone())
    };
    let last2 = match tokens.len() {
        0 => None,
        1 => None,
        n => Some(tokens[n-2].clone())
    };

    // add first previous and next tokens to log msg list
    let mut tokens2_ = match prev1 {
        None => tokens,
        Some(x) => { let mut t = vec![x]; t.append(&mut tokens); t}
    };
    let mut tokens2 = match next1 {
        None => tokens2_,
        Some(x) => { tokens2_.push(x); tokens2_ }
    };
    // calculate 2-grams & add to dictionary. Increment occurance
    for doubles in tokens2.windows(2) {
        let double_tmp = format!("{}^{}", doubles[0], doubles[1]);
	    *dbl.entry(double_tmp.to_owned()).or_default() += 1;
    }

    // add second previous and next tokens to log msg list
    let mut tokens3_ = match prev2 {
        None => tokens2,
        Some(x) => { let mut t = vec![x]; t.append(&mut tokens2); t}
    };
    let tokens3 = match next2 {
        None => tokens3_,
        Some(x) => { tokens3_.push(x); tokens3_ }
    };
    // calculate 3-grams
    for triples in tokens3.windows(3) {
        let triple_tmp = format!("{}^{}^{}", triples[0], triples[1], triples[2]);
	    *trpl.entry(triple_tmp.to_owned()).or_default() += 1;
    }
    return (last1, last2);
}

fn process_dictionary_builder_line_concurrent(line: String, lookahead_line: Option<String>, regexp:&Regex, regexps:&Vec<Regex>, dbl: &mut Arc<DashMap<String, i32>>, trpl: &mut Arc<DashMap<String, i32>>, all_token_list: &mut Vec<String>, prev1: Option<String>, prev2: Option<String>) -> (Option<String>, Option<String>) {
    let (next1, next2) = match lookahead_line {
        None => (None, None),
        Some(ll) => {
            let next_tokens = token_splitter(ll, &regexp, &regexps);
            match next_tokens.len() {
                0 => (None, None),
                1 => (Some(next_tokens[0].clone()), None),
                _ => (Some(next_tokens[0].clone()), Some(next_tokens[1].clone()))
            }
        }
    };

    // log message is split into tokens
    let mut tokens = token_splitter(line, &regexp, &regexps);
    if tokens.is_empty() {
        return (None, None);
    }
    tokens.iter().for_each(|t| if !all_token_list.contains(t) { all_token_list.push(t.clone()) } );

    // keep this for later when we'll return it
    let last1 = match tokens.len() {
        0 => None,
        n => Some(tokens[n-1].clone())
    };
    let last2 = match tokens.len() {
        0 => None,
        1 => None,
        n => Some(tokens[n-2].clone())
    };

    // add first previous and next tokens to log msg list
    let mut tokens2_ = match prev1 {
        None => tokens,
        Some(x) => { let mut t = vec![x]; t.append(&mut tokens); t}
    };
    let mut tokens2 = match next1 {
        None => tokens2_,
        Some(x) => { tokens2_.push(x); tokens2_ }
    };
    // calculate 2-grams & add to dictionary. Increment occurance
    for doubles in tokens2.windows(2) {
        let double_tmp = format!("{}^{}", doubles[0], doubles[1]);
        *dbl.entry(double_tmp.to_owned()).or_default() += 1;
    }

    // add second previous and next tokens to log msg list
    let mut tokens3_ = match prev2 {
        None => tokens2,
        Some(x) => { let mut t = vec![x]; t.append(&mut tokens2); t}
    };
    let tokens3 = match next2 {
        None => tokens3_,
        Some(x) => { tokens3_.push(x); tokens3_ }
    };
    // calculate 3-grams
    for triples in tokens3.windows(3) {
        let triple_tmp = format!("{}^{}^{}", triples[0], triples[1], triples[2]);
        *trpl.entry(triple_tmp.to_owned()).or_default() += 1;
    }
    return (last1, last2);
}

fn dictionary_builder_original(raw_fn: String, format: String, regexps: Vec<Regex>) -> (HashMap<String, i32>, HashMap<String, i32>, Vec<String>) {
    let mut dbl = HashMap::new();
    let mut trpl = HashMap::new();
    let mut all_token_list = vec![];
    let regex = regex_generator(format);

    let mut prev1 = None; let mut prev2 = None;

    if let Ok(lines) = read_lines(raw_fn) {
        let mut lp = lines.peekable();
        loop {
            match lp.next() {
                None => break,
                Some(Ok(ip)) =>
                    match lp.peek() {
                        None =>
                            (prev1, prev2) = process_dictionary_builder_line(ip, None, &regex, &regexps, &mut dbl, &mut trpl, &mut all_token_list, prev1, prev2),
                        Some(Ok(next_line)) =>
                            (prev1, prev2) = process_dictionary_builder_line(ip, Some(next_line.clone()), &regex, &regexps, &mut dbl, &mut trpl, &mut all_token_list, prev1, prev2),
                        Some(Err(_)) => {} // meh, some weirdly-encoded line, throw it out
                    }
                Some(Err(_)) => {} // meh, some weirdly-encoded line, throw it out
            }
        }
    }
    return (dbl, trpl, all_token_list)
}

fn dictionary_builder_seperate(raw_fn: String, format: String, regexps: Vec<Regex>, mut num_threads: usize) -> (HashMap<String, i32>, HashMap<String, i32>, Vec<String>) {
    let regex = regex_generator(format);

    let file: Vec<String> = read_lines(&raw_fn).unwrap().collect::<Result<_, _>>().unwrap();
    let mut chunk_size = file.len() / num_threads;

    // Special case
    if file.len() < num_threads
    {
        chunk_size = 1;
        num_threads = file.len();
    }

    // used for the next chunk
    let mut prev1_global = None;
    let mut prev2_global = None;
    // spawn a thread per chunk
    let mut threads = vec![];
    for i in 0..num_threads
    {
        let file_chunk; // chunk thread will be working one
        let prev1_local = prev1_global.clone(); // last word of previous chunk
        let prev2_local = prev2_global.clone(); // second last word of previous chunk
        let mut next_chunk_line = None; // first line of next chunk

        // if not last chunk, get slice of lines and set next line
        if i != num_threads - 1 { file_chunk = file[i*chunk_size..(i+1)*chunk_size].to_vec(); next_chunk_line = Some(file[(i+1)*chunk_size].clone()) }
        // if last chunk, get rest of lines in file
        else { file_chunk = file[i*chunk_size..].to_vec() }

        // set previous for next chunk
        let mut prev_tokens = token_splitter(file_chunk.last().unwrap().clone(), &regex, &regexps);
        prev1_global = prev_tokens.pop();
        prev2_global = prev_tokens.pop();

        let regex = regex.clone();
        let regexps = regexps.clone();

        // start thread
        threads.push(
            thread::spawn(move || {
                let mut dbl = HashMap::new();   // 2-gram dictionary
                let mut trpl = HashMap::new();  // 3-gram dictionary
                let mut all_token_list = vec![];

                let mut prev1 = prev1_local; let mut prev2 = prev2_local; // Used to reduce bias in starting/ending tokens

                let mut chunk_iter = file_chunk.iter().peekable();
                loop {
                    match chunk_iter.next() { // get line
                        None => break,
                        Some(ip) =>
                            match chunk_iter.peek() { // check next line
                                None =>
                                    (prev1, prev2) = process_dictionary_builder_line(ip.to_string(), next_chunk_line.clone(), &regex, &regexps, &mut dbl, &mut trpl, &mut all_token_list, prev1, prev2),
                                Some(next_line) =>
                                    (prev1, prev2) = process_dictionary_builder_line(ip.to_string(), Some((**next_line).clone()), &regex, &regexps, &mut dbl, &mut trpl, &mut all_token_list, prev1, prev2),
                            }
                    }
                }
                (dbl, trpl, all_token_list)
            })
        );
    }

    // wait for threads and aggregate
    let mut dbl = HashMap::new();
    let mut trpl = HashMap::new();
    let mut all_token_list = vec![];
    for t in threads {
        let result = t.join().unwrap();

        for twograms in result.0.into_iter()
        {
            *dbl.entry(twograms.0).or_default() += twograms.1;
        }
        for threegrams in result.1.into_iter()
        {
            *trpl.entry(threegrams.0).or_default() += threegrams.1;
        }
        result.2.iter().for_each(|t| if !all_token_list.contains(t) { all_token_list.push(t.to_string()) } );
    }

    return (dbl, trpl, all_token_list)
}

fn dictionary_builder_concurrent(raw_fn: String, format: String, regexps: Vec<Regex>, mut num_threads: usize) -> (Arc<DashMap<String, i32>>, Arc<DashMap<String, i32>>, Vec<String>) {
    let regex = regex_generator(format);

    let file: Vec<String> = read_lines(&raw_fn).unwrap().collect::<Result<_, _>>().unwrap();
    let mut chunk_size = file.len() / num_threads;

    let dbl = Arc::new(DashMap::new());   // 2-gram dictionary
    let trpl = Arc::new(DashMap::new());  // 3-gram dictionary

    // Special case
    if file.len() < num_threads
    {
        chunk_size = 1;
        num_threads = file.len();
    }

    // used for the next chunk
    let mut prev1_global = None;
    let mut prev2_global = None;
    // spawn a thread per chunk
    let mut threads = vec![];
    for i in 0..num_threads
    {
        let file_chunk; // chunk thread will be working one
        let prev1_local = prev1_global.clone(); // last word of previous chunk
        let prev2_local = prev2_global.clone(); // second last word of previous chunk
        let mut next_chunk_line = None; // first line of next chunk

        // if not last chunk, get slice of lines and set next line
        if i != num_threads - 1 { file_chunk = file[i*chunk_size..(i+1)*chunk_size].to_vec(); next_chunk_line = Some(file[(i+1)*chunk_size].clone()) }
        // if last chunk, get rest of lines in file
        else { file_chunk = file[i*chunk_size..].to_vec() }

        // set previous for next chunk
        let mut prev_tokens = token_splitter(file_chunk.last().unwrap().clone(), &regex, &regexps);
        prev1_global = prev_tokens.pop();
        prev2_global = prev_tokens.pop();

        let regex = regex.clone();
        let regexps = regexps.clone();
        let mut dbl = dbl.clone();
        let mut trpl = trpl.clone();

        // start thread
        threads.push(
            thread::spawn(move || {
                let mut all_token_list = vec![];

                let mut prev1 = prev1_local; let mut prev2 = prev2_local; // Used to reduce bias in starting/ending tokens

                let mut chunk_iter = file_chunk.iter().peekable();
                loop {
                    match chunk_iter.next() { // get line
                        None => break,
                        Some(ip) =>
                            match chunk_iter.peek() { // check next line
                                None =>
                                    (prev1, prev2) = process_dictionary_builder_line_concurrent(ip.to_string(), next_chunk_line.clone(), &regex, &regexps, &mut dbl, &mut trpl, &mut all_token_list, prev1, prev2),
                                Some(next_line) =>
                                    (prev1, prev2) = process_dictionary_builder_line_concurrent(ip.to_string(), Some((**next_line).clone()), &regex, &regexps, &mut dbl, &mut trpl, &mut all_token_list, prev1, prev2),
                            }
                    }
                }
                all_token_list
            })
        );
    }

    // wait for threads
    let mut all_token_list = vec![];
    for t in threads {
        let result = t.join().unwrap();
        result.iter().for_each(|t| if !all_token_list.contains(t) { all_token_list.push(t.to_string()) } );
    }

    return (dbl, trpl, all_token_list)
}

#[test]
fn test_dictionary_builder_process_line_lookahead_is_none() {
    let line = "Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; user unknown".to_string();
    let re = regex_generator(format_string(&Linux));
    let mut dbl = HashMap::new();
    let mut trpl = HashMap::new();
    let mut all_token_list = vec![];
    let (last1, last2) = process_dictionary_builder_line(line, None, &re, &censored_regexps(&Linux), &mut dbl, &mut trpl, &mut all_token_list, None, None);
    assert_eq!((last1, last2), (Some("unknown".to_string()), Some("user".to_string())));

    let mut dbl_oracle = HashMap::new();
    dbl_oracle.insert("user^unknown".to_string(), 1);
    dbl_oracle.insert("pass;^user".to_string(), 1);
    dbl_oracle.insert("check^pass;".to_string(), 1);
    assert_eq!(dbl, dbl_oracle);

    let mut trpl_oracle = HashMap::new();
    trpl_oracle.insert("pass;^user^unknown".to_string(), 1);
    trpl_oracle.insert("check^pass;^user".to_string(), 1);
    assert_eq!(trpl, trpl_oracle);
}

#[test]
fn test_dictionary_builder_process_line_lookahead_is_some() {
    let line = "Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; user unknown".to_string();
    let next_line = "Jun 14 15:16:02 combo sshd(pam_unix)[19937]: baz bad".to_string();
    let re = regex_generator(format_string(&Linux));
    let mut dbl = HashMap::new();
    let mut trpl = HashMap::new();
    let mut all_token_list = vec![];
    let (last1, last2) = process_dictionary_builder_line(line, Some(next_line), &re, &censored_regexps(&Linux), &mut dbl, &mut trpl, &mut all_token_list, Some("foo".to_string()), Some("bar".to_string()));
    assert_eq!((last1, last2), (Some("unknown".to_string()), Some("user".to_string())));

    let mut dbl_oracle = HashMap::new();
    dbl_oracle.insert("unknown^baz".to_string(), 1);
    dbl_oracle.insert("foo^check".to_string(), 1);
    dbl_oracle.insert("user^unknown".to_string(), 1);
    dbl_oracle.insert("pass;^user".to_string(), 1);
    dbl_oracle.insert("check^pass;".to_string(), 1);
    assert_eq!(dbl, dbl_oracle);

    let mut trpl_oracle = HashMap::new();
    trpl_oracle.insert("pass;^user^unknown".to_string(), 1);
    trpl_oracle.insert("check^pass;^user".to_string(), 1);
    trpl_oracle.insert("unknown^baz^bad".to_string(), 1);
    trpl_oracle.insert("foo^check^pass;".to_string(), 1);
    trpl_oracle.insert("bar^foo^check".to_string(), 1);
    trpl_oracle.insert("user^unknown^baz".to_string(), 1);
    assert_eq!(trpl, trpl_oracle);
}

pub fn parse_raw_original(raw_fn: String, lf:&LogFormat) -> (HashMap<String, i32>, HashMap<String, i32>, Vec<String>) {
    let (double_dict, triple_dict, all_token_list) = dictionary_builder_original(raw_fn, format_string(&lf), censored_regexps(&lf));
    println!("double dictionary list len {}, triple {}, all tokens {}", double_dict.len(), triple_dict.len(), all_token_list.len());
    return (double_dict, triple_dict, all_token_list);
}

pub fn parse_raw_seperate(raw_fn: String, lf:&LogFormat, num_threads: usize) -> (HashMap<String, i32>, HashMap<String, i32>, Vec<String>) {
    let (double_dict, triple_dict, all_token_list) = dictionary_builder_seperate(raw_fn, format_string(&lf), censored_regexps(&lf), num_threads);
    println!("double dictionary list len {}, triple {}, all tokens {}", double_dict.len(), triple_dict.len(), all_token_list.len());
    return (double_dict, triple_dict, all_token_list);
}

pub fn parse_raw_concurrent(raw_fn: String, lf:&LogFormat, num_threads: usize) -> (Arc<DashMap<String, i32>>, Arc<DashMap<String, i32>>, Vec<String>) {
    let (double_dict, triple_dict, all_token_list) = dictionary_builder_concurrent(raw_fn, format_string(&lf), censored_regexps(&lf), num_threads);
    println!("double dictionary list len {}, triple {}, all tokens {}", double_dict.len(), triple_dict.len(), all_token_list.len());
    return (double_dict, triple_dict, all_token_list);
}

// compares output of parse_raw_seperate to original
#[test]
fn test_seperate_correctness() {

    let files = HashMap::from([
        (String::from("data/from_paper.log"), &Spark),
        (String::from("data/HDFS_2k.log"), &HDFS),
        (String::from("data/HealthApp_2k.log"), &HealthApp),
        (String::from("data/HealthApp.log"), &HealthApp),
        (String::from("data/HPC_2k.log"), &HPC),
        (String::from("data/HPC.log"), &HPC),
        (String::from("data/Linux_2k.log"), &Linux),
        (String::from("data/Linux.log"), &Linux),
        (String::from("data/openstack_abnormal.log"), &OpenStack),
        (String::from("data/openstack_normal1.log"), &OpenStack),
        (String::from("data/openstack_normal2.log"), &OpenStack),
        (String::from("data/Proxifier_2k.log"), &Proxifier),
        (String::from("data/Proxifier.log"), &Proxifier)
    ]);

    for file in files
    {
        println!("{}", file.0);
        let (double_dict, triple_dict, all_token_list) = parse_raw_original(file.0.clone(), file.1);
        let (double_dict_single, triple_dict_single, all_token_list_single) = parse_raw_seperate(file.0, file.1, 8);

        assert_eq!(double_dict, double_dict_single);
        assert_eq!(triple_dict, triple_dict_single);
        assert_eq!(all_token_list, all_token_list_single);
    }
}

// compares output of parse_raw_concurrent to original
#[test]
fn test_concurrent_correctness() {

    let files = HashMap::from([
        (String::from("data/from_paper.log"), &Spark),
        (String::from("data/HDFS_2k.log"), &HDFS),
        (String::from("data/HealthApp_2k.log"), &HealthApp),
        (String::from("data/HealthApp.log"), &HealthApp),
        (String::from("data/HPC_2k.log"), &HPC),
        (String::from("data/HPC.log"), &HPC),
        (String::from("data/Linux_2k.log"), &Linux),
        (String::from("data/Linux.log"), &Linux),
        (String::from("data/openstack_abnormal.log"), &OpenStack),
        (String::from("data/openstack_normal1.log"), &OpenStack),
        (String::from("data/openstack_normal2.log"), &OpenStack),
        (String::from("data/Proxifier_2k.log"), &Proxifier),
        (String::from("data/Proxifier.log"), &Proxifier)
    ]);

    for file in files
    {
        println!("{}", file.0);
        let (double_dict, triple_dict, all_token_list) = parse_raw_original(file.0.clone(), file.1);
        let (double_dict_conc, triple_dict_conc, all_token_list_conc) = parse_raw_concurrent(file.0, file.1, 8);

        let double_dict_conc = Arc::try_unwrap(double_dict_conc).unwrap().into_iter().collect::<HashMap<_,_>>();
        let triple_dict_conc = Arc::try_unwrap(triple_dict_conc).unwrap().into_iter().collect::<HashMap<_,_>>();

        assert_eq!(double_dict, double_dict_conc);
        assert_eq!(triple_dict, triple_dict_conc);
        assert_eq!(all_token_list, all_token_list_conc);
    }
}

#[test]
fn test_parse_raw_linux() {
    let (double_dict, triple_dict, all_token_list) = parse_raw_original("data/from_paper.log".to_string(), &Linux);
    let all_token_list_oracle = vec![
        "hdfs://hostname/2kSOSP.log:21876+7292".to_string(),
        "hdfs://hostname/2kSOSP.log:14584+7292".to_string(),
        "hdfs://hostname/2kSOSP.log:0+7292".to_string(),
        "hdfs://hostname/2kSOSP.log:7292+7292".to_string(),
        "hdfs://hostname/2kSOSP.log:29168+7292".to_string()
    ];
    assert_eq!(all_token_list, all_token_list_oracle);
    let mut double_dict_oracle = HashMap::new();
    double_dict_oracle.insert("hdfs://hostname/2kSOSP.log:14584+7292^hdfs://hostname/2kSOSP.log:0+7292".to_string(), 2);
    double_dict_oracle.insert("hdfs://hostname/2kSOSP.log:21876+7292^hdfs://hostname/2kSOSP.log:14584+7292".to_string(), 2);
    double_dict_oracle.insert("hdfs://hostname/2kSOSP.log:7292+7292^hdfs://hostname/2kSOSP.log:29168+7292".to_string(), 2);
    double_dict_oracle.insert("hdfs://hostname/2kSOSP.log:0+7292^hdfs://hostname/2kSOSP.log:7292+7292".to_string(), 2);
    assert_eq!(double_dict, double_dict_oracle);
    let mut triple_dict_oracle = HashMap::new();
    triple_dict_oracle.insert("hdfs://hostname/2kSOSP.log:0+7292^hdfs://hostname/2kSOSP.log:7292+7292^hdfs://hostname/2kSOSP.log:29168+7292".to_string(), 1);
    triple_dict_oracle.insert("hdfs://hostname/2kSOSP.log:14584+7292^hdfs://hostname/2kSOSP.log:0+7292^hdfs://hostname/2kSOSP.log:7292+7292".to_string(), 1);
    triple_dict_oracle.insert("hdfs://hostname/2kSOSP.log:21876+7292^hdfs://hostname/2kSOSP.log:14584+7292^hdfs://hostname/2kSOSP.log:0+7292".to_string(), 1);
    assert_eq!(triple_dict, triple_dict_oracle);
}

/// standard mapreduce invert map: given {<k1, v1>, <k2, v2>, <k3, v1>}, returns ([v1, v2] (sorted), {<v1, [k1, k3]>, <v2, [k2]>})
pub fn reverse_dict(d: &HashMap<String, i32>) -> (BTreeSet<i32>, HashMap<i32, Vec<String>>) {
    let mut reverse_d: HashMap<i32, Vec<String>> = HashMap::new();
    let mut val_set: BTreeSet<i32> = BTreeSet::new();

    for (key, val) in d.iter() {
        if reverse_d.contains_key(val) {
            let existing_keys = reverse_d.get_mut(val).unwrap();
            existing_keys.push(key.to_string());
        } else {
            reverse_d.insert(*val, vec![key.to_string()]);
            val_set.insert(*val);
        }
    }
    return (val_set, reverse_d);
}

pub fn reverse_dict_concurrent(d: Arc<DashMap<String, i32>>) -> (BTreeSet<i32>, HashMap<i32, Vec<String>>) {
    let mut reverse_d: HashMap<i32, Vec<String>> = HashMap::new();
    let mut val_set: BTreeSet<i32> = BTreeSet::new();

    for kv in d.iter() {
        if reverse_d.contains_key(kv.value()) {
            let existing_keys = reverse_d.get_mut(kv.value()).unwrap();
            existing_keys.push(kv.key().clone());
        } else {
            reverse_d.insert(*kv.value(), vec![kv.key().to_string()]);
            val_set.insert(*kv.value());
        }
    }
    return (val_set, reverse_d);
}

pub fn print_dict(s: &str, d: &HashMap<String, i32>) {
    let (val_set, reverse_d) = reverse_dict(d);

    println!("printing dict: {}", s);
    for val in &val_set {
        println!("{}: {:?}", val, reverse_d.get(val).unwrap());
    }
    println!("---");
}

pub fn print_dict_concurrent(s: &str, d: &Arc<DashMap<String, i32>>) {
    let (val_set, reverse_d) = reverse_dict_concurrent(d.clone());

    println!("printing dict: {}", s);
    for val in &val_set {
        println!("{}: {:?}", val, reverse_d.get(val).unwrap());
    }
    println!("---");
}

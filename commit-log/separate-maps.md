Parallelized Dictionary Builder using Seperate Maps

Summary:
Created threads to process different chunks of the log in parallel. Each thread has it's own dictionaries in which it populates with ngrams from its chunk. The dictionaries are then combined and aggregated in the main thread.

Tech details:
The entire log is loaded into memory at once. For every thread, an even chunk of the log is cloned and given to that thread. The thread then saves the line after it's chunk and it's last two tokens to ensure every token appears equally when transforming to ngrams.

Each thread then proceeds normally on its own chunk, iterating through each line and adding 2grams & 3grams to their respective hashmap.

The main thread waits for spawned threads to return and aggregates each of their dictionaries sequentially into its own dictionary.

Correctness:
I wrote functions test_seperate_correctness() to test correctness of my implementation. They go through each log and compare output of parse_raw_seperate() to parse_raw_original().

Performance:
I ran hyperfine on the original and modified code to compare performance. A few warmup rounds were ran first to fill up the cache to reduce varience in the results.
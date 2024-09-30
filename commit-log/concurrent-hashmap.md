Parallelized Dictionary Builder using Concurrent Map

Summary:
Created threads to process different chunks of the log in parallel. Each thread shares a dictionary in which it populates with ngrams from its chunk concurrently.

Tech details:
The entire log is loaded into memory at once. For every thread, an even chunk of the log is cloned and given to that thread. The thread then saves the line after it's chunk and it's last two tokens to ensure every token appears equally when transforming to ngrams.

Each thread then proceeds normally on its own chunk, iterating through each line and adding 2grams & 3grams to the shared hashmaps. The hashmaps were wrapped in an Arc pointer and cloned to each thread to allow sharing. The "Dashmap" library was used for a thread safe hashmap.

The main thread waits for spawned threads to return and directly returns the shared hashmaps.

Correctness:
I wrote functions test_concurrent_correctness() to test correctness of my implementation. They go through each log and compare output of parse_raw_concurrent() to parse_raw_original().

Performance:
I ran hyperfine on the original and modified code to compare performance. A few warmup rounds were ran first to fill up the cache to reduce varience in the results.
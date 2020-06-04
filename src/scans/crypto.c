/*
 1. cat /proc/sys/kernel/random/entropy_avail > 200
 2. Determine if system uses encrypted swap
 3. Determine if system uses LUKS block device encryption
 4. check for expired SSL certificates
 5. Test for presence of hardware random number generators
 6. Test for presence of software pseudo random number generators
 7. https://github.com/CISOfy/lynis/blob/ce3c80b44f418e28503e1aecaeb87c170d0c811c/include/tests_crypto
*/
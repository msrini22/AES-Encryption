# libaes
This project implements the AES standard as defined by NIST as a library in C

# Build Instructions
## Library
Move to the `lib` directory and execute `make`. The headers are present in `lib/includes` and the library itself will be present in 
`lib/bin`


You can link the libaes.a statically with any driver of your choice.

## Sample
The `test` directory contains a sample code, as well a python test harness. To execute the test harness, first compile the library
and then use `make` to compile the implementation sample. The test can be executed as `./test_aes.py`

The input test vectors are present in the `input_vectors.txt` file

 

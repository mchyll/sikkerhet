#include <string>
#include <iostream>
#include <random>
#include <sstream>

using namespace std;

vector<char> hex_to_bytes(const string& hex) {
    vector<char> bytes;

    for (size_t i = 0; i < hex.length(); i += 2) {
        string byte_string = hex.substr(i, 2);
        bytes.push_back((char) strtol(byte_string.c_str(), nullptr, 16));
    }

    return bytes;
}

/*
 * Oppgave 2
 * Genererer en nøkkelstrøm. Gjør XOR mellom bytene i cipherteksten
 * og nøkkelstrømen og får bytene til klarteksten.
 */
int main() {
    string ciphertext = "114b70745a521c57371f7a245d6440662d49";
    string key = "Dette er en noekkel";

    //Create seed from key
    seed_seq seed(key.begin(), key.end());

    //Choice of pseudorandom number generator using the given seed
    minstd_rand0 generator(seed);

    //Choice of distribution with 1 byte values
    uniform_int_distribution<char> distribution;

    //Retrieve random numbers from the generator using the chosen distribution:
    /*for (size_t c = 0; c < 5; ++c) {
        cout << (int) distribution(generator) << endl;
    }*/

    cout << "Meldingen dekryptert:" << endl;
    vector<char> cipher_bytes = hex_to_bytes(ciphertext);
    for (char byte : cipher_bytes) {
        char c = (char) ((int) distribution(generator) ^ byte);
        cout << c;
    }
    cout << endl;
}

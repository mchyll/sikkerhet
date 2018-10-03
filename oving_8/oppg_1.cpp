#include <string>
#include <iostream>

using namespace std;

/*
 * Oppgave 1
 * Cipherteksten er kryptert med en slags Cæsarkoding, hvor hvert tegn
 * sin ASCII-verdi er forskjøvet med et tall som utgjør nøkkelen.
 */
int main() {
    string ciphertext = "judwxohuhuCghuhCkduCixqqhwCphoglqjhqD";

    for (int i = -40; i < 40; i++) {
        cout << "Prøver med nøkkel " << i << ": ";
        for (auto& character : ciphertext) {
            cout << static_cast<char>(character + i);
        }
        cout << endl;
    }
}

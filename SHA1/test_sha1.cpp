#include "sha1.h"
#include <string>
#include <iostream>
using std::string;
using std::cout;
using std::endl;


void compare(const string &result, const string &expected) {
    const string &state = (result == expected) ? "OK" : "Failure";
    cout << "Result:   " << result << endl;
    cout << "Expected: " << expected << "  (" << state << ")" << endl;
}


/*
 * The 3 test vectors from FIPS PUB 180-1
 */

void test_standard() {
    SHA1 checksum;

    cout << endl;
    cout << "Test:     abc" << endl;
    checksum.update("abc");
    compare(checksum.final(), "a9993e364706816aba3e25717850c26c9cd0d89d");

    cout << endl;
    cout << "Test:     kejunjie2012011335" << endl;
    checksum.update("kejunjie2012011335");
    compare(checksum.final(), "9d830070688eeff8ac33cd306cb017fc201e0b5f");

    cout << endl;
    cout << "Test:     ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" << endl;
    checksum.update("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    compare(checksum.final(), "761c457bf73b14d27e9e9265c46f4b4dda11f940");

    cout << endl;
    cout << "Test:     A million repetitions of 'a'" << endl;
    for (int i = 0; i < 1000000/200; ++i)
    {
        checksum.update("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                       );
    }
    compare(checksum.final(), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}


/*
 * Other tests
 */

void test_other() {
    SHA1 checksum;

    cout << endl;
    cout << "Test:     No string" << endl;
    compare(checksum.final(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    cout << endl;
    checksum.update("");
    cout << "Test:     Empty string" << endl;
    compare(checksum.final(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}


/*
 * immitate "sha1sum -b"
 */

void test_file(const string &filename) {
    cout << SHA1::from_file(filename) << " *" << filename << endl;
}


/*
 * main
 */

int main(int argc, const char *argv[])
{
    if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
        {
            test_file(argv[i]);
        }
    }
    else
    {
        test_standard();
        test_other();
        cout << endl;
        cout << endl;
    }

    return 0;
}

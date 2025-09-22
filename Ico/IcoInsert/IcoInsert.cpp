#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

// Encode
std::string replaceHexDigits(const std::string& hexString) {
    std::string replaced;
    for (char c : hexString) {
        if (c >= '0' && c <= '9') {
            replaced.push_back('g' + (c - '0'));
        }
        else {
            replaced.push_back(c);
        }
    }
    return replaced;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage : " << argv[0] << " <.bin input_file> <.ico output_file>" << std::endl;
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];

    std::ifstream input(input_file, std::ios::binary);
    if (!input) {
        std::cerr << "Error : can't open the input file " << input_file << std::endl;
        return 1;
    }

    // read the data Stream
    std::ostringstream oss;
    oss << input.rdbuf();
    std::string binary_data = oss.str();

    // Convert Binary tp Hex
    std::ostringstream hex_stream;
    for (unsigned char c : binary_data) {
        hex_stream << std::setw(2) << std::setfill('0') << std::hex << (int)c;
    }

    std::string hex_string = hex_stream.str();

    std::string replaced_hex = replaceHexDigits(hex_string);

    std::ofstream output(output_file);
    if (!output) {
        std::cerr << "Error : can't open the output file : " << output_file << std::endl;
        return 1;
    }

    output << replaced_hex;

    input.close();
    output.close();

    std::cout << "everything it's OK " << output_file << std::endl;

    return 0;
}

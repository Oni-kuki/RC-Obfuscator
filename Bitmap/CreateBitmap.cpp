#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>

#pragma pack(push, 1)
// File Header configuration
struct BMPFileHeader {
    uint16_t bfType = 0x4D42;        
    uint32_t bfSize;                
    uint16_t bfReserved1 = 0;       
    uint16_t bfReserved2 = 0;       
    uint32_t bfOffBits = 54;        
};

struct BMPInfoHeader {
    uint32_t biSize = 40;          
    int32_t biWidth;               
    int32_t biHeight;              
    uint16_t biPlanes = 1;         
    uint16_t biBitCount = 24;      
    uint32_t biCompression = 0;    
    uint32_t biSizeImage;          
    int32_t biXPelsPerMeter = 0;   
    int32_t biYPelsPerMeter = 0;   
    uint32_t biClrUsed = 0;        
    uint32_t biClrImportant = 0;   
};
#pragma pack(pop)

void createSmallerBMP(const std::string& filename, int width, int height) {

    int rowSize = (3 * width + 3) & ~3; 
    int imageSize = rowSize * height;

    BMPFileHeader fileHeader;
    BMPInfoHeader infoHeader;

    // Header config
    fileHeader.bfSize = sizeof(BMPFileHeader) + sizeof(BMPInfoHeader) + imageSize;
    infoHeader.biWidth = width;
    infoHeader.biHeight = height;
    infoHeader.biSizeImage = imageSize;

    // Pixel init
    std::vector<uint8_t> pixels(imageSize, 0);
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            int index = y * rowSize + x * 3;

            // Dynamic colors
            uint8_t red = static_cast<uint8_t>((sin(x * 0.2) + 1) * 127);   // sinus 
            uint8_t green = static_cast<uint8_t>((cos(y * 0.2) + 1) * 127); //  cosinus
            uint8_t blue = static_cast<uint8_t>((x + y) % 256);

            // specific defined zone
            if (x > width / 3 && x < 2 * width / 3 && y > height / 3 && y < 2 * height / 3) {
                red = 255;   
                green = 0;
                blue = 0;
            }
            else if (x < width / 4 || y < height / 4) {
                red = 0;
                green = 255; 
                blue = 0;
            }

            // affect RGB 
            pixels[index] = blue;
            pixels[index + 1] = green;
            pixels[index + 2] = red;
        }
    }

    // write 
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error : impossible to create file" << filename << "\n";
        return;
    }

    file.write(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
    file.write(reinterpret_cast<char*>(&infoHeader), sizeof(infoHeader));
    file.write(reinterpret_cast<char*>(pixels.data()), pixels.size());

    file.close();
    std::cout << "BMP file created : " << filename << "\n";
}

int main() {
    createSmallerBMP("smaller_output.bmp", 266, 200); // 266x200 pixels
    return 0;
}

#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <span>
#include <filesystem>
#include <fstream>

#include <boost/multiprecision/cpp_int.hpp>


class Ex : public std::exception
{
public:

  Ex() : exception{}, mSS{ std::make_shared<std::stringstream>() }, mStr{}
  {
  }

  template<typename T>
  Ex& operator<<( T const& t )
  {
    *mSS << t;
    return *this;
  }

  char const* what() const noexcept override
  {
    mStr = mSS->str();
    return mStr.c_str();
  }

private:
  std::shared_ptr<std::stringstream> mSS;
  mutable std::string mStr;
};

static constexpr size_t LOADER_BLOCK_LENGTH = 50;
static constexpr size_t LOADER_CHUNK_LENGTH = LOADER_BLOCK_LENGTH + 1;

using namespace boost::multiprecision;
using namespace boost::multiprecision::literals;

uint512_t constexpr lynxpubmod = 0x35b5a3942806d8a22695d771b23cfd561c4a19b6a3b02600365a306e3c4d63381bd41c136489364cf2ba2a58f4fee1fdac7e79_cppui512;
uint512_t constexpr lynxprvexp = 0x23ce6d0d7004906c19b93a4bcc28a8e412dc11246d2019557987ab5ca818a3d3c8e3276d4270cb8021d6bda4296d47b1e5e2a3_cppui512;
uint512_t constexpr lynxpubexp = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003_cppui512;

void encrypt( std::array<uint8_t, LOADER_BLOCK_LENGTH> const& plain_block, uint8_t& accumulator, std::vector<uint8_t>& result )
{
  std::array<uint8_t, LOADER_CHUNK_LENGTH> block{};
  block[LOADER_CHUNK_LENGTH - 1] = 0x15; //last byte must be 0x15

  auto out = block.begin();

  for ( uint8_t elem : plain_block )
  {
    *out++ = elem - accumulator;
    accumulator = elem;
  }

  uint512_t plain;

  import_bits( plain, block.begin(), block.end(), 8, false );
  uint512_t encr = powm( plain, lynxprvexp, lynxpubmod );
  export_bits( encr, std::back_inserter( result ), 8, false );
}

std::vector<uint8_t> encrypt( std::span<uint8_t const> plain )
{
  std::vector<uint8_t> result{ 0 };

  if ( plain.size() > LOADER_BLOCK_LENGTH * 5 )
    throw Ex{} << "Maximum loader size is 250 bytes";

  uint8_t accumulator = 0;
  for ( size_t i = 0; i < plain.size(); i += LOADER_BLOCK_LENGTH )
  {
    std::array<uint8_t, LOADER_BLOCK_LENGTH> plain_block{};
    size_t size = std::min( plain.size() - i, LOADER_BLOCK_LENGTH );
    std::copy_n( plain.begin() + i, size, plain_block.begin() );
    encrypt( plain_block, accumulator, result );
    result[0] -= 1;
  }

  if ( ( accumulator & 0xff ) != 0 )
  {
    throw Ex{} << "Sanity check final accumulator value 0x" << std::hex << (int)accumulator << " != 0x00. loader must leave at least one 0 byte at the end";
  }

  return result;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> parseXex( std::span<uint8_t const> xex )
{
  if ( xex.size() < 7 || xex[0] != 0xff && xex[1] != 0xff || xex[2] != 0x00 || xex[3] != 0x02 )
  {
    return { encrypt( xex ), std::vector<uint8_t>{} };
  }

  uint16_t start = ( (uint16_t*)xex.data() )[1];
  uint16_t stop = ( (uint16_t*)xex.data() )[2];
  uint16_t size = stop - start + 1;

  if ( xex.size() < size + 6 )
    throw Ex{} << "Bad xex";

  std::span<uint8_t const> loader{ xex.data() + 6, xex.data() + 6 + size };
  std::vector<uint8_t> rest{ xex.begin() + 6 + size, xex.end() };

  return { encrypt( loader ), rest };
}

int main( int argc, char const* argv[] )
{
  try
  {
    if ( argc != 3 )
    {
      std::cout << "Humble Another Minimal Lynx Encryption Tool. Usage:\n\n";
      std::cout << "HAMLET\tinput.xex output.bin\tgenerates loader only\n\tinput.xex output.lyx\tfills image to 256k to be readable by AgaCart.\n\n";
      std::cout << "If input file is in Atari xex format, only first block is encrypted, rest is appended as is,\n";
      std::cout << "otherwise the whole input file is encrypted.\n";
      return 1;
    }

    std::filesystem::path path{ argv[1] };
    std::filesystem::path outpath{ argv[2] };

    if ( !std::filesystem::exists( path ) )
    {
      throw Ex{} << "File '" << path.string() << "' does not exist\n";
    }

    size_t size = std::filesystem::file_size( path );

    if ( size == 0 )
    {
      throw Ex{} << "File '" << path.string() << "' is empty\n";
    }

    std::vector<uint8_t> input;
    input.resize( size );

    {
      std::ifstream fin{ path, std::ios::binary };
      fin.read( (char*)input.data(), size );
    }

    auto [loader, rest] = parseXex( { input.data(), size } );

    if ( outpath.extension() == ".lyx" )
    {
      rest.resize( 256 * 1024 - loader.size(), 0xff );
    }

    std::ofstream fout{ outpath, std::ios::binary };
    fout.write( (char const*)loader.data(), loader.size() );
    if ( !rest.empty() )
      fout.write( (char const*)rest.data(), rest.size() );
  }
  catch ( Ex const& ex )
  {
    std::cerr << ex.what() << std::endl;
    return -1;
  }

  return 0;

}

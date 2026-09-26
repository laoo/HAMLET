#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <span>
#include <filesystem>
#include <fstream>
#include <array>
#include <optional>
#include <algorithm>
#include <string_view>


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

//What the encryption needs of a big number library, and no more of it: the modulus of the Lynx's key is 51 bytes and
//both exponents are constants of the format, so one fixed width is the whole requirement. A number is held least
//significant byte first, which is the order the cartridge carries it in. Exponentiation is by squaring, over a modular
//multiply that doubles and adds, so nothing here divides - and long division, the one part of this arithmetic with
//corner cases worth fearing, never appears. Every step acts on a value below twice the modulus, which the one
//subtraction it can need brings back below it.

static constexpr size_t NUMBER_LENGTH = LOADER_CHUNK_LENGTH; //51 bytes: the modulus, and every number beside it

using Num = std::array<uint8_t, NUMBER_LENGTH>;

//A number as a key is written, most significant digit first. Constant evaluated, so a literal of the wrong length or
//with a digit that is not one does not compile.
constexpr Num fromHex( std::string_view digits )
{
  if ( digits.size() != NUMBER_LENGTH * 2 )
    throw std::logic_error{ "a number of this key is 102 hexadecimal digits" };

  Num result{};

  for ( size_t i = 0; i < digits.size(); ++i )
  {
    char const digit = digits[i];
    uint8_t value = 0;

    if ( digit >= '0' && digit <= '9' )
      value = (uint8_t)( digit - '0' );
    else if ( digit >= 'a' && digit <= 'f' )
      value = (uint8_t)( digit - 'a' + 10 );
    else if ( digit >= 'A' && digit <= 'F' )
      value = (uint8_t)( digit - 'A' + 10 );
    else
      throw std::logic_error{ "not a hexadecimal digit" };

    size_t const position = NUMBER_LENGTH - 1 - i / 2; //the digits come highest byte first
    result[position] = (uint8_t)( ( result[position] << 4 ) | value );
  }

  return result;
}

//The boot ROM carries this modulus and checks each block with the public exponent 3. What encrypts one is the private
//exponent, which is public knowledge.
static constexpr Num lynxpubmod = fromHex( "35b5a3942806d8a22695d771b23cfd561c4a19b6a3b02600365a306e3c4d63381bd41c136489364cf2ba2a58f4fee1fdac7e79" );
static constexpr Num lynxprvexp = fromHex( "23ce6d0d7004906c19b93a4bcc28a8e412dc11246d2019557987ab5ca818a3d3c8e3276d4270cb8021d6bda4296d47b1e5e2a3" );

//a += b, and whether it carried out of the top.
static bool addTo( Num& a, Num const& b )
{
  unsigned carry = 0;

  for ( size_t i = 0; i < NUMBER_LENGTH; ++i )
  {
    unsigned const sum = (unsigned)a[i] + b[i] + carry;
    a[i] = (uint8_t)sum;
    carry = sum >> 8;
  }

  return carry != 0;
}

//a -= b, and whether it borrowed past the top.
static bool subtractFrom( Num& a, Num const& b )
{
  unsigned borrow = 0;

  for ( size_t i = 0; i < NUMBER_LENGTH; ++i )
  {
    unsigned const difference = (unsigned)a[i] - b[i] - borrow;
    a[i] = (uint8_t)difference;
    borrow = ( difference >> 8 ) & 1;
  }

  return borrow != 0;
}

//a <<= 1, and the bit that left the top.
static bool doubleIt( Num& a )
{
  unsigned carry = 0;

  for ( size_t i = 0; i < NUMBER_LENGTH; ++i )
  {
    unsigned const shifted = ( (unsigned)a[i] << 1 ) | carry;
    a[i] = (uint8_t)shifted;
    carry = shifted >> 8;
  }

  return carry != 0;
}

static bool isBelow( Num const& a, Num const& b )
{
  for ( size_t i = NUMBER_LENGTH; i-- > 0; )
  {
    if ( a[i] != b[i] )
      return a[i] < b[i];
  }

  return false;
}

static bool bitOf( Num const& a, size_t bit )
{
  return ( ( a[bit / 8] >> ( bit % 8 ) ) & 1 ) != 0;
}

//( a * b ) mod modulus, for a and b below it: the bits of b from the top, doubling what is held and adding a where the
//bit is set.
static Num multiplyMod( Num const& a, Num const& b, Num const& modulus )
{
  Num result{};

  for ( size_t bit = NUMBER_LENGTH * 8; bit-- > 0; )
  {
    bool const over = doubleIt( result );
    if ( over || !isBelow( result, modulus ) )
      subtractFrom( result, modulus );

    if ( bitOf( b, bit ) )
    {
      bool const carried = addTo( result, a );
      if ( carried || !isBelow( result, modulus ) )
        subtractFrom( result, modulus );
    }
  }

  return result;
}

//( base ^ exponent ) mod modulus, for base below it.
static Num powerMod( Num const& base, Num const& exponent, Num const& modulus )
{
  Num result{};
  result[0] = 1;

  for ( size_t bit = NUMBER_LENGTH * 8; bit-- > 0; )
  {
    result = multiplyMod( result, result, modulus );

    if ( bitOf( exponent, bit ) )
      result = multiplyMod( result, base, modulus );
  }

  return result;
}

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

  //The block is the number, and its highest byte is the 0x15 above - below the modulus, whose highest byte is 0x35, so
  //every block is a number this key carries.
  Num plain{};
  std::copy( block.begin(), block.end(), plain.begin() );

  Num const encrypted = powerMod( plain, lynxprvexp, lynxpubmod );

  result.insert( result.end(), encrypted.begin(), encrypted.end() );

  //Exactly 51 bytes, always, because that is what the number is held in: the boot ROM reads 51 for every block, and a
  //block written without its leading zeroes - which about one in fifty has - would shift every block after it.
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

struct XexParsingResult
{
  std::span<uint8_t const> optHeader;
  std::vector<uint8_t> loader;
  std::vector<uint8_t> rest;
};

XexParsingResult parseXex( std::span<uint8_t const> xex )
{
  if ( xex.size() < 7 || xex[0] != 0xff && xex[1] != 0xff )
  {
    return { std::span<uint8_t const>{}, encrypt( xex ), std::vector<uint8_t>{} };
  }

  xex = xex.subspan( 2 );

  uint16_t start = ( (uint16_t*)xex.data() )[0];
  uint16_t stop = ( (uint16_t*)xex.data() )[1];
  uint16_t size = stop - start + 1;

  std::span<uint8_t const> header;

  if ( start == 0x0000 && size == 0x40 )
  {
    header = xex.subspan( 4, 0x40 );
    xex = xex.subspan( 0x44 );
    if ( xex[0] == 0xff && xex[1] == 0xff )
      xex = xex.subspan( 2 );
    start = ( (uint16_t*)xex.data() )[0];
    stop = ( (uint16_t*)xex.data() )[1];
    size = stop - start + 1;
  }

  if ( xex.size() < size )
    throw Ex{} << "Bad xex";

  if ( start != 0x200 )
    throw Ex{} << "Loader block must start at $200";

  std::span<uint8_t const> loader{ xex.data() + 4, xex.data() + 4 + size };
  std::vector<uint8_t> rest{ xex.begin() + 4 + size, xex.end() };

  return { header, encrypt( loader ), rest };
}

int main( int argc, char const* argv[] )
{
  try
  {
    if ( argc != 2 )
    {
      std::cout << "Humble Another Minimal Lynx Encryption Tool. Usage:\n\n";
      std::cout << "HAMLET\tinput\n";
      return 1;
    }

    std::filesystem::path path{ argv[1] };
    std::filesystem::path outpath = path;

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

    auto [header, loader, rest] = parseXex( { input.data(), size } );


    if ( header.empty() )
    {
      outpath.replace_extension( ".lyx" );
      rest.resize( 256 * 1024 - loader.size(), 0xff );
    }
    else if ( !rest.empty() )
    {
      outpath.replace_extension( ".lnx" );
      size_t pageSize = header[5] * 256;
      size_t restSize = ( ( rest.size() + loader.size() + pageSize - 1 ) / pageSize ) * pageSize - loader.size();
      rest.resize( restSize, 0xff );
    }
    else
    {
      if ( outpath.has_extension() && outpath.extension() == ".bin" )
        outpath.replace_extension( ".loader" );
      else
        outpath.replace_extension( ".bin" );
    }

    std::ofstream fout{ outpath, std::ios::binary };
    if ( !header.empty() )
      fout.write( (char const*)header.data(), header.size() );
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

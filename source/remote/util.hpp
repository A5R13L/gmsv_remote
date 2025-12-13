#include <filesystem>
#include <vector>
#include <string>
#include <fstream>
#include <regex>

static const size_t SEARCH_CHUNK_SIZE = 128 * 1024;

struct MatchPosition_t
{
    size_t Offset;
    size_t Length;
};

struct MatchInfo_t
{
    int Line;
    int MatchStart;
    int MatchEnd;
    std::string LineText;
};

inline char lower(char Character)
{
    return (Character >= 'A' && Character <= 'Z') ? (Character + 32) : Character;
}

static bool IsWordCharacter(char Character)
{
    return std::isalnum((unsigned char)Character) || Character == '_';
}

static bool IsWholeWord(const std::string &Text, size_t Position, size_t Length)
{
    bool leftOK = (Position == 0 || !IsWordCharacter(Text[Position - 1]));
    bool rightOK = (Position + Length >= Text.size() || !IsWordCharacter(Text[Position + Length]));
    return leftOK && rightOK;
}

static std::vector<size_t> BMH_Search(const std::string &Text, const std::string &Needle, bool CaseSensitive)
{
    std::vector<size_t> Matches;
    const size_t NeedleLength = Needle.size();
    const size_t TextLength = Text.size();

    if (NeedleLength == 0 || TextLength < NeedleLength)
        return Matches;

    std::string NeedleLower = Needle;

    if (!CaseSensitive)
        for (char &Character : NeedleLower)
            Character = lower(Character);

    uint8_t MatchTable[256];

    for (int Index = 0; Index < 256; Index++)
        MatchTable[Index] = NeedleLength;

    for (size_t Index = 0; Index < NeedleLength - 1; Index++)
    {
        char Character = NeedleLower[Index];
        MatchTable[(uint8_t)Character] = NeedleLength - 1 - Index;
    }

    size_t IDX = 0;

    while (IDX <= TextLength - NeedleLength)
    {
        bool Match = true;

        for (size_t Index = 0; Index < NeedleLength; Index++)
        {
            char HaystackCharacter = Text[IDX + Index];
            char NeedleCharacter = NeedleLower[Index];

            if (!CaseSensitive)
                HaystackCharacter = lower(HaystackCharacter);

            if (HaystackCharacter != NeedleCharacter)
            {
                Match = false;
                break;
            }
        }

        if (Match)
        {
            Matches.push_back(IDX);
            IDX += NeedleLength;
            continue;
        }

        char Character = Text[IDX + NeedleLength - 1];

        if (!CaseSensitive)
            Character = lower(Character);

        IDX += MatchTable[(uint8_t)Character];
    }

    return Matches;
}

static std::vector<MatchPosition_t> Stream_Search(std::ifstream &FileStream, const std::string &Needle,
                                                  bool CaseSensitive)
{
    std::vector<MatchPosition_t> Matches;
    const size_t NeedleLength = Needle.size();

    if (NeedleLength == 0)
        return Matches;

    static thread_local std::string Buffer;
    Buffer.resize(SEARCH_CHUNK_SIZE + NeedleLength);

    std::string NeedleLower = Needle;

    if (!CaseSensitive)
        for (char &Character : NeedleLower)
            Character = lower(Character);

    size_t Offset = 0;

    while (FileStream)
    {
        FileStream.read(&Buffer[0], SEARCH_CHUNK_SIZE);

        size_t BytesRead = FileStream.gcount();

        if (BytesRead == 0)
            break;

        for (size_t Index = 0; Index + NeedleLength <= BytesRead; Index++)
        {
            bool Match = true;

            for (size_t ID = 0; ID < NeedleLength; ID++)
            {
                char TextLength = Buffer[Index + ID];

                if (!CaseSensitive)
                    TextLength = lower(TextLength);

                if (TextLength != NeedleLower[ID])
                {
                    Match = false;
                    break;
                }
            }

            if (Match)
                Matches.push_back({Offset + Index, NeedleLength});
        }

        Offset += BytesRead;

        if (BytesRead >= NeedleLength - 1)
            std::memmove(&Buffer[0], &Buffer[BytesRead - (NeedleLength - 1)], NeedleLength - 1);
    }

    return Matches;
}

static MatchInfo_t Stream_ExtractMatchInfo(const std::filesystem::path &Path, size_t MatchOffset, size_t MatchLen)
{
    MatchInfo_t MatchInfo = {};

    MatchInfo.Line = 0;
    MatchInfo.MatchStart = 0;
    MatchInfo.MatchEnd = 0;

    std::ifstream FileStream(Path, std::ios::binary);

    if (!FileStream)
        return MatchInfo;

    size_t LineStart = 0;
    size_t LineEnd = 0;

    {
        size_t Scan = (MatchOffset > 4096 ? MatchOffset - 4096 : 0);
        size_t Size = MatchOffset - Scan;

        std::string Block(Size, '\0');
        FileStream.seekg(Scan);
        FileStream.read(&Block[0], Size);

        for (size_t Index = Block.size(); Index-- > 0;)
        {
            if (Block[Index] == '\n')
            {
                LineStart = Scan + Index + 1;
                break;
            }
        }
    }

    {
        FileStream.clear();
        FileStream.seekg(MatchOffset);

        const size_t FILE_CHUNK_SIZE = 4096;
        char Buffer[FILE_CHUNK_SIZE];

        size_t Position = MatchOffset;

        while (FileStream)
        {
            FileStream.read(Buffer, FILE_CHUNK_SIZE);
            size_t Bytes = FileStream.gcount();
            if (Bytes == 0)
                break;

            for (size_t Index = 0; Index < Bytes; Index++)
            {
                if (Buffer[Index] == '\n')
                {
                    LineEnd = Position + Index;
                    goto EndOfMatch;
                }
            }

            Position += Bytes;
        }

        LineEnd = Position;

    EndOfMatch:;
    }

    {
        size_t Length = LineEnd - LineStart;
        MatchInfo.LineText.resize(Length);

        FileStream.clear();
        FileStream.seekg(LineStart);
        FileStream.read(MatchInfo.LineText.data(), Length);
    }

    MatchInfo.MatchStart = int(MatchOffset - LineStart);
    MatchInfo.MatchEnd = MatchInfo.MatchStart + MatchLen;

    {
        FileStream.clear();
        FileStream.seekg(0);

        char Buffer[4096];
        size_t Total = 0;
        int Line = 0;

        while (Total < LineStart && FileStream)
        {
            FileStream.read(Buffer, sizeof(Buffer));

            size_t Bytes = FileStream.gcount();

            if (Bytes == 0)
                break;

            for (size_t Index = 0; Index < Bytes && Total + Index < LineStart; Index++)
                if (Buffer[Index] == '\n')
                    Line++;

            Total += Bytes;
        }

        MatchInfo.Line = Line;
    }

    return MatchInfo;
}

static bool Glob_Match(const std::string &Pattern, const std::string &Text)
{
    size_t ID = 0, Size = 0, StartPosition = std::string::npos, Match = 0;

    while (Size < Text.size())
    {
        if (ID < Pattern.size() && (Pattern[ID] == '?' || Pattern[ID] == Text[Size]))
        {
            ID++;
            Size++;
        }
        else if (ID < Pattern.size() && Pattern[ID] == '*')
        {
            StartPosition = ID++;
            Match = Size;
        }
        else if (StartPosition != std::string::npos)
        {
            ID = StartPosition + 1;
            Size = ++Match;
        }
        else
            return false;
    }

    while (ID < Pattern.size() && Pattern[ID] == '*')
        ID++;

    return ID == Pattern.size();
}

static std::vector<std::string> Split_Patterns(const std::string &Text)
{
    std::vector<std::string> Matches;
    std::string Current;

    for (char Character : Text)
    {
        if (Character == ',')
        {
            if (!Current.empty())
            {
                size_t First = Current.find_first_not_of(' ');
                size_t Second = Current.find_last_not_of(' ');

                if (First != std::string::npos)
                    Matches.push_back(Current.substr(First, Second - First + 1));

                Current.clear();
            }
        }
        else
            Current.push_back(Character);
    }

    if (!Current.empty())
    {
        size_t First = Current.find_first_not_of(' ');
        size_t Second = Current.find_last_not_of(' ');

        if (First != std::string::npos)
            Matches.push_back(Current.substr(First, Second - First + 1));
    }

    return Matches;
}

static bool Matches_Any(const std::vector<std::string> &Patterns, const std::string &Path)
{
    if (Patterns.empty())
        return false;

    for (const auto &Pattern : Patterns)
        if (Glob_Match(Pattern, Path))
            return true;

    return false;
}

static bool matches_none(const std::vector<std::string> &Patterns, const std::string &Path)
{
    if (Patterns.empty())
        return true;

    for (const auto &Pattern : Patterns)
        if (Glob_Match(Pattern, Path))
            return false;

    return true;
}

static std::vector<MatchPosition_t> Stream_SearchRegex(const std::filesystem::path &Path, const std::string &Pattern,
                                                       bool CaseSensitive)
{
    std::vector<MatchPosition_t> Matches;
    std::ifstream FileStream(Path, std::ios::binary);

    if (!FileStream)
        return Matches;

    static thread_local std::string Buffer;
    size_t Overlap = 512;
    std::regex_constants::syntax_option_type Flags = std::regex_constants::ECMAScript;

    Buffer.clear();
    Buffer.reserve(SEARCH_CHUNK_SIZE + Overlap * 2);

    if (!CaseSensitive)
        Flags |= std::regex_constants::icase;

    std::regex Regex;

    try
    {
        Regex = std::regex(Pattern, Flags);
    }
    catch (const std::regex_error &)
    {
        return Matches;
    }

    size_t AbsoluteOffset = 0;

    while (true)
    {
        std::string Chunk;

        Chunk.resize(SEARCH_CHUNK_SIZE);
        FileStream.read(Chunk.data(), SEARCH_CHUNK_SIZE);

        size_t Bytes = FileStream.gcount();

        if (Bytes == 0)
            break;

        Chunk.resize(Bytes);

        std::string SearchBuffer = Buffer + Chunk;
        std::smatch StringMatch;

        auto Begin = SearchBuffer.cbegin();
        auto End = SearchBuffer.cend();

        while (std::regex_search(Begin, End, StringMatch, Regex))
        {
            size_t Local = (Begin - SearchBuffer.cbegin()) + StringMatch.position();
            size_t GlobalPosition = AbsoluteOffset - Buffer.size() + Local;

            Matches.push_back({GlobalPosition, (size_t)StringMatch.str().size()});

            Begin += StringMatch.position() + StringMatch.size();
        }

        if (SearchBuffer.size() > Overlap)
            Buffer = SearchBuffer.substr(SearchBuffer.size() - Overlap);
        else
            Buffer = SearchBuffer;

        AbsoluteOffset += Bytes;
    }

    return Matches;
}
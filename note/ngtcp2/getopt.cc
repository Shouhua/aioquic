#include <getopt.h>
#include <iostream>

struct Config
{
    bool quiet;
};

Config config{};

int main(int argc, char *argv[])
{
    while (1)
    {
        int long_index = 0;
        opterr = 0;
        struct option long_opt[] = {
            {"quiet", 0, nullptr, 'q'},
            {0, 0, 0, 0}};
        auto c = getopt_long(argc, argv, ":vq::", long_opt, &long_index);
        if (c == -1)
            break;
        switch (c)
        {
        case '?':
            std::cout << "? getopt error occured: " << optopt << std::endl;
            break;
        case ':':
            std::cout << ": getopt error occured: " << optopt << std::endl;
            break;
        case 'q':
            std::cout << "getopt handle quiet option: " << optarg << std::endl;
            break;
        }
    }
    if (argc - optind < 2)
    {
        std::cout << "Usage: " << argv[0] << "[-q|--quiet] HOST PORT" << std::endl;
        exit(-1);
    }
    auto host = argv[optind++];
    auto port = argv[optind++];
    std::cout << "host: " << host << " port: " << port << std::endl;
    return 0;
}
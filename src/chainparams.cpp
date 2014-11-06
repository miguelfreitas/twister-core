// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "core.h"
#include "protocol.h"
#include "util.h"

//
// Main network
//

unsigned int pnSeed[] =
{
    0x3db2528b, 0x609ec836, 0x90e9156b, 0x22b2528b, 0xa0cfa5bc, 0x9ad19f55, 0x66b2528b, 0x29b9b992,
    0x5bc3f6da, 0xd9baa76b, 0xd6d626cf, 0xf77ddf4e, 0x4a2e555f, 0x677c98c8, 0xd683b992, 0x76068b25,
    0xf216ba6a, 0x55efaa6b, 0x829a3eb2, 0x886f8a43, 0xdda23eb2, 0x62248f68, 0x7c1afc2e, 0xfda00a51,
    0xae97e757, 0x72218368, 0x468bfeb6, 0x7ff9d9a2, 0x80a03eb2, 0xb9994cad, 0x5ab6b95d, 0xea4ec268,
    0x77eebb25, 0xaca34305, 0x522ad176, 0x5713a4d8, 0x4530dc1f, 0xc6a053d4, 0x0f58e9bc, 0x9d743ac6,
    0x97d59dc0, 0x0ad35872, 0x8c5cc818, 0xcd5cd454, 0x75af3851, 0xce0e255c, 0xad0be9bc, 0x3cc4482e,
    0x6a902002, 0x28d4482e, 0xfc22a068, 0x0c862442, 0x45dae64e, 0x0454b259, 0x37bd1dd9, 0x4122555f,
    0xaec8cc47, 0xa08ad54e, 0x165df950, 0x1c3cad6f, 0xb8324ada, 0xeb6d3ac6, 0xd85ce362, 0x89ffba32,
    0x48c5e052, 0xb2ecd048, 0x3f5e9c5a, 0xe68ba1cb, 0xe40ec273, 0xf3035272, 0x8068777d, 0x30cdc973,
    0x778ad54e, 0x44bb48de, 0x8bc6bb25, 0x48515d72, 0x344dfd54, 0x4a9d0e7d, 0xc22ad0a2, 0x41671bb2,
    0x3261690e, 0xc49e206e, 0x5dc27161, 0xc5aba33e, 0x543eddd8, 0x65c3eb7a, 0x74456077, 0xca56c082,
    0x8885cc25, 0xfb61fc6d, 0xb4af7a7d, 0x06fbd05e, 0x3ac9482e, 0x7894f472, 0x36e60401, 0x6b5e787d,
    0xf022c2bc, 0x2f37be6d, 0xd1bfb87c, 0x4289206e, 0xdcc41dc9, 0x8deb0401, 0x72e50401, 0x5d27bbbc,
    0x4e46c281, 0xe7aa0e79, 0x6d25105a, 0x8570bd12, 0x5ae0574f, 0x1212b37c, 0xcb24f874, 0x1395f1ba,
    0x03fe0401, 0x7eba16c9, 0xeec4ba56, 0x721cbd54, 0x1ca8e95e, 0x61c31f5d, 0x4eb2528b, 0xab2dbd54,
    0x30154605, 0xc02fa43a, 0x37b5a056, 0x608b20bc, 0xb5a6505d, 0x8c6b2549, 0xa036546a, 0x9afbe44f,
    0xd2465d72, 0xe3be1dc9, 0xf3cd8cb2, 0xdcd25872, 0x69f60401, 0x3e347059, 0x9c595d72, 0x45c8e179,
    0xd4bdea4e, 0x9b69695c, 0xa79ab07c, 0x5993d46d, 0x6846c36e, 0xc5d6d5ba, 0xaf2c61b1, 0xb9419cba,
    0xe7fa9d6d, 0x34d3846d, 0x49a2301f, 0x75a2767d, 0xb8a208af, 0xf688b455, 0x53a3135d, 0xe89dfc71,
    0xe72abd54, 0x35f0e44f, 0x5f22ec59, 0x0a90b455, 0x989ab54f, 0x27ababb4, 0xab682cbc, 0x236b828a,
    0x706b5d02, 0x6237787b, 0x9dc17470, 0xf9d2126e, 0x890bf572, 0xdf500c87, 0x296a6d2e, 0x10fad5ba,
    0xfee0533e, 0x6d297059, 0xa500bd54, 0x0b43c36e, 0x5fa88156, 0x93de5658, 0x898aa53d, 0x83c15a4b,
    0xd0f2717b, 0xe13ab4af, 0xbbcb482e, 0x13af254e, 0x92d2d5ba, 0x27810477, 0xe683b455, 0x8c7ff12e,
    0x7626bb58, 0xccf86c4e, 0xbc86b455, 0xf3e7ba58, 0x29845d02, 0x02e10bc6, 0xe569e352, 0x2b2a173a,
    0x3b8d6944, 0xc5740a1b, 0x1ef9d5ba, 0x48e58b50, 0xf7ab3244, 0x3038c26e, 0x4c51e08c, 0xc51c4150,
    0x67c85dab, 0x5470a243, 0x4a5434c9, 0x3144c170, 0x9676e36d, 0x1b28b458, 0x3052690e, 0xa6afc6dd,
    0xfc15b2d4, 0x1054972e, 0xe5ea0401, 0xa1031bbd, 0x9c2bcc62, 0x97d7cd9f, 0xd09df3a2, 0xaef5055a,
    0x9050e08c, 0xe07d4605, 0x293925b0, 0xceabf1ba, 0x15bf454b, 0x05c4505d, 0xd67cf972, 0x0ce81dc9,
    0xc6d90db7, 0x52f1a07c, 0xe7e0ed82, 0xc9cdd5ba, 0x901ef2b6, 0x8bf6cd2e, 0x36f5c36e, 0x1d5f6f4f,
    0xacd9d5ba, 0x62533e46, 0xa7a130ba, 0x6ef79c3e, 0x094a225b, 0xf492787d, 0x0b69cdb1, 0x4968cdb1,
    0x4baf728d, 0x79505d72, 0xa38ab455, 0xbda2a165, 0xee4d9f1b, 0xd82b2c5c, 0xbe2b9e7b, 0xe39dd6ba,
    0xbf9af1ba, 0xfc455d72, 0xc538d879, 0x6e8ea065, 0xfb529389, 0xd14af976, 0x87f0c36e, 0xbc4ac36e,
    0x47811855, 0xcd0ab86e, 0x50dc164d, 0xb8dad73c, 0xaca4598f, 0x70a648de, 0xc3ded5ba, 0x9f55372e,
    0x3a465d72, 0x181819ad, 0xfd9bcd3e, 0xeb50e08c, 0x21500c87, 0x10bcae3b, 0xe2e9a377, 0xec54fe18,
    0x7399d6ba, 0x88480852, 0x33e89389, 0x16c01b3c, 0x1b789aa5, 0x4f903a4d, 0xbfb0a658, 0x4af6cd2e,
    0x3f76690e, 0x43c0002e, 0x8ad255df, 0x5333d91b, 0x57b8b858, 0x7474507a, 0x4c04a63a, 0xe6add6ba,
    0x120e1874, 0x4141c86e, 0xe3a4f872, 0xcf2b41de, 0xb2c57cb2, 0xe48bc22e, 0x54f34250, 0x7efb1974,
    0x8850e08c, 0x6082eadd, 0x2f1a1bbd, 0x91c3ff5c, 0xf0ed6b54, 0x9240507a, 0x199fc257, 0x38266b51,
    0x4d500c87, 0xd2d8b47c, 0xb28f8368, 0x431aa0b4, 0x5d5be974, 0xd2e90a1b, 0xb6756377, 0xe2f3ae55,
    0x9bb04371, 0x8d940db7, 0x71797080, 0x33e8d979, 0x0b86be6b, 0xb9b8f371, 0xe8ced6ab, 0x9562fbb0,
    0x9803be6d, 0x9d9dfc71, 0x1544c170, 0x9e139473, 0x429b0344, 0x8c8232ba, 0x376d4071, 0x329dfc71,
    0x7e586171, 0x775a5975, 0x5c38e670, 0x5151375f, 0xfd8d2d70, 0x706b60b8, 0x839a1853, 0x4a585378,
    0x65c5c39e, 0xef8eb67b, 0x30e36871, 0x4cda0eb0, 0xdff947b2, 0x387e692e, 0x6a53787b, 0xf4b0a56f,
    0x5312a932, 0xfcad9389, 0xbd500c87, 0x6a48b756, 0x53644465, 0x982c1bbd, 0x860322b7, 0xbc84b455,
    0x5295d2b2, 0x46fea6dc, 0x0a97b455, 0x841db05b, 0xe7be750e, 0xd58c4305, 0xd2fcae55, 0xd1e31dc9,
    0x1708e9dc, 0x624479c0, 0x89d49e7c, 0x88a9be6d, 0x52855718, 0xb8d1dd72, 0x88524252, 0x6f88253a,
    0xd0b1fc3a, 0x23cf106e, 0x375f0653, 0xcd892218, 0x8c1f4f59, 0x1bb9303d, 0xa08c11b7, 0x980f27b7,
    0xa7ed84b1, 0xad93b8dc, 0x7d50e08c, 0xc73bd9de, 0x7c566c59, 0x3705b47c, 0x299dfc71, 0x1113ee4e,
    0x935b6270, 0xebfc727b, 0xd0a11c75, 0x74ced6ab, 0x29987e0e, 0xcaad16d2, 0x9e0e1801, 0xc94fc268,
    0x8d92cd18, 0x2bced6ab, 0xc78ae75a, 0xccb02843, 0xf292506a, 0x37af7871, 0x6a22a068, 0xc665063c,
    0x0cc0fc1b, 0xe2aa0e79, 0xa7a0b032, 0x0a6d58b6, 0x92a49eba, 0xbc4bf771, 0xcb5a9bc0, 0x90bd3077,
    0xfccb5171, 0x56fa5971, 0xc5baa77c, 0xd4861e53, 0x463e2db7, 0x274b7274, 0x1fa2a956, 0xa1e89bb4,
    0xd7da0db7, 0x7997b455, 0x621f173a, 0xa31df57b, 0xe6a4598f, 0x449f1787, 0xa4a1dd57, 0x5300bb25,
    0x8a9331c3, 0xc08d1874, 0xc2733156, 0x3097357b, 0xb835787b, 0x1ad3884f, 0xef822442, 0xb185844b,
    0x524f6270, 0xf6eb0a1b, 0xfa4b5372, 0x99e94c74, 0x995e4131, 0x85de46b2, 0xf2e4b47b, 0x02e71dc9,
    0xe988b455, 0xa702c074, 0xb82588d9, 0x9e632c6a, 0xb6d255df, 0xb30925b7, 0xd0142475, 0x5ff1ae55,
    0xd977aa6b, 0x603cefdd, 0x54a7de73, 0x7f1ef151, 0x5fb75a7c, 0x2c9c0a75, 0x586bdfdd, 0x191f8eca,
    0xc1a30a51, 0xbd0f737b, 0x7825c22e, 0x7ed99b6e, 0x5e075e46, 0xf7011bc5, 0x4e090f75, 0xa5a5d147,
    0x4edbe118, 0xc7851a75, 0x6841e029, 0x51cb9a3e, 0x8d161a5e, 0x68bea24d, 0x5554211f, 0x200ef572,
    0x4c0fc818, 0xd98ff03a, 0x1071f752, 0xcf1e126e, 0x479bb455, 0xb645146e, 0x83c7b7b2, 0xa7fde172,
    0xc960c76f, 0x42bb1a5e, 0xfc6f4665, 0x0ccb9a3e, 0x3f3eddd8, 0x17005272, 0xfda0fc3a, 0xcc8c11b7,
    0x565acb45, 0x9947c6b4, 0xf571ba3c, 0x4325d779, 0x0e990c75, 0x0cb1106e, 0x1f1e173a, 0xebbc1fb0,
    0xbbfc1dc9, 0xbb961874, 0xdce2175c, 0x12ab7174, 0x3e20f371, 0xaad5f872, 0xada9d73c, 0x7a001374,
    0xa01eb37b, 0x15e9f872, 0xf931f531, 0xeab34d7c, 0x16b0b757, 0x1d710553, 0xe9857374, 0x11bf926e,
    0x20913a55, 0x2fa30a56, 0xc35826ca, 0xef33e369, 0x2c92b869, 0x5fa15c5c, 0x408556c9, 0x9af40d56,
    0x2d725572, 0x23af7174, 0xa6ea09b0, 0x9f5c5070, 0x7cb35453, 0x2c4e11be, 0x8437eb7a, 0x047dc073,
    0x02d92b7c, 0xf6e0a6d4, 0xe7056db4, 0xe52ab03c, 0xf5a241de, 0xe72415b7, 0x4eab5670, 0xd5d40db7,
    0xce3fc76f, 0x72908d3d, 0x3134136e, 0x9c039832, 0x18581c53, 0x0a8d1dda, 0x30ec6bb4, 0x2b679056,
    0x148fe217, 0x7085815c, 0x308bdf2e, 0xe177ea3c, 0x3d825070, 0x47f48c3d, 0x2ac7e65b, 0xeb2ebc5e,
    0x6e73bc43, 0xf6aa5670, 0x1eda4475, 0x3ddc545f, 0x936d76b4, 0xd3d9e36f, 0x14365d02, 0x9f32a8dc,
    0x5ad5106a, 0xa09d82b6, 0x8c9a357b, 0x91c7546a, 0x5700c074, 0xce8cf0df, 0xa1c74c6f, 0xcc625c72,
    0x3c3285b7, 0x72e433b7, 0xe347225b, 0xdf1db37b, 0xc7cb273a, 0xeceaa277, 0x529dfc71, 0xce651974,
    0xddc02f5b, 0x95302172, 0x0da2e374, 0x5615c46e, 0x0c626570, 0x030f4a80, 0x2f0f9cb7, 0xfc8b7d6a,
    0x618dff3a, 0xf5776d5e, 0x1372ceb4, 0xc4757a61, 0xce62b82a, 0x90a94f4d, 0xd981bf7a, 0x3c7cdb71,
    0x4aaee95e, 0xdc5c6670, 0x63a55b70, 0xbdf0622a, 0x807a3c3a, 0xf2a236b7, 0x5a48f7de, 0xbd77787d
};

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xf0;
        pchMessageStart[1] = 0xda;
        pchMessageStart[2] = 0xbb;
        pchMessageStart[3] = 0xd2;
        vAlertPubKey = ParseHex("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");
        nDefaultPort = 28333;
        nRPCPort = 28332;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        nTxBits = 0x1e00ffff;
        nSubsidyHalvingInterval = 210000;

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        //
        // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
        //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
        //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
        //   vMerkleTree: 4a5e1e
        const char* pszTimestamp = "The Times 09/Jul/2013 Globo caught bribing Receita Federal employee to rob R$615M worth tax evasion documents.";
        CTransaction txNew;
        txNew.message = CScript() << string(pszTimestamp);
        txNew.userName = CScript() << string("nobody");
        txNew.nNonce  = 0; // spamMessage is not required to show POW to ease "extranonce" support
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nHeight  = 0;
        genesis.nTime    = 1384394255;
        //genesis.nBits    = 0x1d00ffff;
        genesis.nBits    = 0x1f03ffff;
        genesis.nNonce   = 2934;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("9915158279673d101912be80f25c20627f1dd8bf5231e7c46bfec5ed19737f44"));

        vSeeds.push_back(CDNSSeedData("twister.net.co", "seed.twister.net.co"));
        vSeeds.push_back(CDNSSeedData("gombadi.com", "dnsseed.gombadi.com"));
        vSeeds.push_back(CDNSSeedData("twister.net.co", "seed2.twister.net.co"));
        vSeeds.push_back(CDNSSeedData("twister.net.co", "seed3.twister.net.co"));
        vSeeds.push_back(CDNSSeedData("twisterseed.tk", "twisterseed.tk"));
        vSeeds.push_back(CDNSSeedData("cruller.tasty.sexy", "cruller.tasty.sexy"));

        base58Prefixes[PUBKEY_ADDRESS] = 0;
        base58Prefixes[SCRIPT_ADDRESS] = 5;
        base58Prefixes[SECRET_KEY] = 128;

        // Convert the pnSeeds array into usable address objects.
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,
            // it'll get a pile of addresses with newer timestamps.
            // Seed nodes are given a random 'last seen time' of between one and two
            // weeks ago.
            const int64 nOneWeek = 7*24*60*60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
            vFixedSeeds.push_back(addr);
        }
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (v3)
//
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        vAlertPubKey = ParseHex("04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a");
        nDefaultPort = 18333;
        nRPCPort = 18332;
        strDataDir = "testnet3";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1296688602;
        genesis.nNonce = 414098458;
        hashGenesisBlock = genesis.GetHash();
        //assert(hashGenesisBlock == uint256("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org"));
        //vSeeds.push_back(CDNSSeedData("bluematt.me", "testnet-seed.bluematt.me"));

        base58Prefixes[PUBKEY_ADDRESS] = 111;
        base58Prefixes[SCRIPT_ADDRESS] = 196;
        base58Prefixes[SECRET_KEY] = 239;

    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nSubsidyHalvingInterval = 150;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        nTxBits = 0x207fffff;
        genesis.nTime = 1296688602;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 2;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18444;
        strDataDir = "regtest";
        //assert(hashGenesisBlock == uint256("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.

        base58Prefixes[PUBKEY_ADDRESS] = 0;
        base58Prefixes[SCRIPT_ADDRESS] = 5;
        base58Prefixes[SECRET_KEY] = 128;
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}

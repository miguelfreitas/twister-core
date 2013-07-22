// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "bitcoinrpc.h"
#include <boost/algorithm/string/predicate.hpp>

void DetectShutdownThread(boost::thread_group* threadGroup)
{
    bool shutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (!shutdown)
    {
        MilliSleep(200);
        shutdown = ShutdownRequested();
    }
    if (threadGroup)
        threadGroup->interrupt_all();
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
bool AppInit(int argc, char* argv[])
{
    boost::thread_group threadGroup;
    boost::thread* detectShutdownThread = NULL;

    bool fRet = false;
    try
    {
        //
        // Parameters
        //
        // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main()
        ParseParameters(argc, argv);
        if (!boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified directory does not exist\n");
            Shutdown();
        }
        ReadConfigFile(mapArgs, mapMultiArgs);

        if (mapArgs.count("-?") || mapArgs.count("--help"))
        {
            // First part of help message is specific to bitcoind / RPC client
            std::string strUsage = _("Bitcoin version") + " " + FormatFullVersion() + "\n\n" +
                _("Usage:") + "\n" +
                  "  bitcoind [options]                     " + "\n" +
                  "  bitcoind [options] <command> [params]  " + _("Send command to -server or bitcoind") + "\n" +
                  "  bitcoind [options] help                " + _("List commands") + "\n" +
                  "  bitcoind [options] help <command>      " + _("Get help for a command") + "\n";

            strUsage += "\n" + HelpMessage();

            fprintf(stdout, "%s", strUsage.c_str());
            return false;
        }

        // Command-line RPC
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "bitcoin:"))
                fCommandLine = true;

        if (fCommandLine)
        {
            if (!SelectParamsFromCommandLine()) {
                fprintf(stderr, "Error: invalid combination of -regtest and -testnet.\n");
                return false;
            }
            int ret = CommandLineRPC(argc, argv);
            exit(ret);
        }
#if !defined(WIN32)
        fDaemon = GetBoolArg("-daemon", false);
        if (fDaemon)
        {
            // Daemonize
            pid_t pid = fork();
            if (pid < 0)
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false;
            }
            if (pid > 0) // Parent process, pid is child process id
            {
                CreatePidFile(GetPidFile(), pid);
                return true;
            }
            // Child process falls through to rest of initialization

            pid_t sid = setsid();
            if (sid < 0)
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
#endif

        detectShutdownThread = new boost::thread(boost::bind(&DetectShutdownThread, &threadGroup));
        fRet = AppInit2(threadGroup);
    }
    catch (std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }
    if (!fRet) {
        if (detectShutdownThread)
            detectShutdownThread->interrupt();
        threadGroup.interrupt_all();
    }

    if (detectShutdownThread)
    {
        detectShutdownThread->join();
        delete detectShutdownThread;
        detectShutdownThread = NULL;
    }
    Shutdown();

    return fRet;
}

static bool TestCreateSpamMsgTx()
{
    CTransaction txNew;

    txNew.message = CScript() << vector<unsigned char>((const unsigned char*)strSpamMessage.data(), (const unsigned char*)strSpamMessage.data() + strSpamMessage.size());

    CKey key;
    key.MakeNewKey(true);

    // compute message hash and sign it
    CHashWriter msgHash(SER_GETHASH, PROTOCOL_VERSION);
    msgHash << txNew.message;
    // vchSig is sig(hash(message))
    vector<unsigned char> vchSig;
    if (!key.Sign(msgHash.GetHash(), vchSig)) {
        printf("CreateNewBlock: Failed to sign SpamMessage\n");
        return false;
    }
    CScript signedHash = CScript() << vector<unsigned char>((const unsigned char*)vchSig.data(), (const unsigned char*)vchSig.data() + vchSig.size());
    printf("CreateSpamMsgTx: msg = %s user = %s hash = %s signedhash = %s\n", txNew.message.ToString().c_str(), strSpamUser.c_str(),
           msgHash.GetHash().ToString().c_str(), signedHash.ToString().c_str() );
    // add username and signature
    txNew.userName = CScript() << vector<unsigned char>((const unsigned char*)strSpamUser.data(), (const unsigned char*)strSpamUser.data() + strSpamUser.size());
    txNew.userName += signedHash;
    txNew.pubKey.clear(); // pubKey will be updated to include extranonce
    txNew.nNonce = 0; // no update needed for spamMessage's nonce.

    std::vector< std::vector<unsigned char> > vData;
    txNew.userName.ExtractPushData(vData);

    CPubKey pubkey( key.GetPubKey() );
    printf("Verify: %d VerifyComp: %d\n",
           pubkey.Verify(msgHash.GetHash(),vData[1]),
           pubkey.VerifyCompact(msgHash.GetHash(),vData[1]));

    return true;
}

extern void GenesisMiner();
extern void noui_connect();
int main(int argc, char* argv[])
{
    bool fRet = false;
    fHaveGUI = false;

    //GenesisMiner();

    // Connect bitcoind signal handlers
    noui_connect();

    fRet = AppInit(argc, argv);

    TestCreateSpamMsgTx();

    if (fRet && fDaemon)
        return 0;

    return (fRet ? 0 : 1);
}

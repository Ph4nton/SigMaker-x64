#include "Misc.h"

bool HasOneHitSig( qSigVector& vecSig )
{
    for (AutoSig_t& iterSig : vecSig)
    {
        if (iterSig.iHitCount == 1)
            return true;
    }
    return false;
}

int GetOccurenceCount( const qstring& strSig, bool bSkipOut = false )
{
    int iCount = 0;
    ea_t dwAddress = find_binary(inf.omin_ea, inf.omax_ea, strSig.c_str(), 16, SEARCH_DOWN);
    if (IsValidEA(dwAddress))
    {
	do
	{
		if (bSkipOut == true && iCount >= 2)
			return iCount;
		iCount++;
		dwAddress = find_binary(dwAddress + 1, inf.omax_ea, strSig.c_str(), 16, SEARCH_DOWN);
	} while (IsValidEA(dwAddress));
    }
    return iCount;
}

void SearchForSigs( const qstring& strSig )
{
    const char* pszMessage = "======================\n";

    msg( pszMessage );

	ea_t dwAddress = find_binary(inf.omin_ea, inf.omax_ea, strSig.c_str(), 16, SEARCH_DOWN);

	if (IsValidEA(dwAddress))
	{
		do
		{
			msg("Singnature Found at %llX\n", dwAddress);
			dwAddress = find_binary(dwAddress + 1, inf.omax_ea, strSig.c_str(), 16, SEARCH_DOWN);
		} while (IsValidEA(dwAddress));
	}

    msg( pszMessage );
}

void ShowSearchDialog(void) //Code
{
	static const char szForm[] =
		"Test Sig\n"
		"\n"
		"\n"
		"  <Signature:A5:200:200::>\n"
		"  <Mask:A6:100:100::>\n"
		"\n";

	qstring strSig, strSigCode;
	ea_t dwStart, dwEnd;

	if (read_range_selection(get_current_viewer(), &dwStart, &dwEnd))
	{
		if (dwEnd - dwStart > 5)
		{
			insn_t cmd;

			func_item_iterator_t fIterator;
			bool isWithinRange = fIterator.set_range(dwStart, dwEnd);

			for (ea_t dwCurrentInstruction = fIterator.current();
				decode_insn(&cmd, dwCurrentInstruction) != 0;
				dwCurrentInstruction = fIterator.current())
			{
				if (cmd.size < 5)
					AddBytesToSig(strSig, dwCurrentInstruction, cmd.size);
				else
					AddInsToSig(&cmd, strSig);

				if (fIterator.next_not_tail() == false)
					break;
			}
		}
	}

	char szSignature[MAXSTR] = { 0 }, szMask[MAXSTR] = { 0 };

	if (strSig.length() > 3)
		qstrncpy(szSignature, strSig.c_str(), sizeof(szSignature));

	if (ask_form(szForm, szSignature, szMask) > 0)
	{
		show_wait_box("please wait...");
		CodeToIDA(strSigCode, szSignature, szMask);
		SearchForSigs(strSigCode);
		hide_wait_box();
	}
}

void ShowSearchWindow( void ) // IDA
{
    static const char szForm[] =
        "Test Sig\n"
        "\n"
        "\n"
        "  <Signature:A5:200:200::>\n"
        "\n";

    qstring strSig;
    ea_t dwStart, dwEnd;

    if (read_range_selection( get_current_viewer( ), &dwStart, &dwEnd ))
    {
        if (dwEnd - dwStart > 5)
        {
            insn_t cmd;

            func_item_iterator_t fIterator;
            bool isWithinRange = fIterator.set_range( dwStart, dwEnd );

            for (ea_t dwCurrentInstruction = fIterator.current( );
                decode_insn( &cmd, dwCurrentInstruction ) != 0;
                dwCurrentInstruction = fIterator.current( ))
            {
                if (cmd.size < 5)
                    AddBytesToSig( strSig, dwCurrentInstruction, cmd.size );
                else
                    AddInsToSig( &cmd, strSig );

                if (fIterator.next_not_tail( ) == false)
                    break;
            }
        }
    }

    char szSignature[MAXSTR] = { 0 };

    if (strSig.length( ) > 3)
        qstrncpy( szSignature, strSig.c_str( ), sizeof( szSignature ) );

    if (ask_form( szForm, szSignature ) > 0)
    {
        show_wait_box( "please wait..." );
        qstring strSig = szSignature;
        SearchForSigs( strSig );
        hide_wait_box( );
    }
}

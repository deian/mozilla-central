/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 *
 * The contents of this file are subject to the Netscape Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/NPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is mozilla.org code.
 *
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 1998 Netscape Communications Corporation. All
 * Rights Reserved.
 *
 * Contributor(s): 
 */

#include "prsystem.h"

#include "nsMessenger.h"

// xpcom
#include "nsIComponentManager.h"
#include "nsIServiceManager.h"
#include "nsFileStream.h"
#include "nsIStringStream.h"
#include "nsEscape.h"
#include "nsXPIDLString.h"
#include "nsTextFormatter.h"

// necko
#include "nsMimeTypes.h"
#include "nsIURL.h"
#include "nsIStreamListener.h"
#include "nsIStreamConverterService.h"
#include "nsNetUtil.h"

// rdf
#include "nsIRDFCompositeDataSource.h"
#include "nsIRDFResource.h"
#include "nsIRDFService.h"
#include "nsRDFCID.h"

// gecko
#include "nsLayoutCID.h"
#include "nsIMarkupDocumentViewer.h"
#include "nsIContentViewerFile.h"
#include "nsIContentViewer.h" 

/* for access to docshell */
#include "nsIDOMWindowInternal.h"
#include "nsIScriptGlobalObject.h"
#include "nsIDocShell.h"
#include "nsIDocShellTreeItem.h"
#include "nsIDocShellTreeNode.h"
#include "nsIWebNavigation.h"

// mail
#include "nsMsgUtils.h"
#include "nsMsgBaseCID.h"
#include "nsIMsgAccountManager.h"
#include "nsIMsgMailSession.h"

#include "nsIMsgFolder.h"
#include "nsMsgFolderFlags.h"
#include "nsIMsgIncomingServer.h"

#include "nsIMsgMessageService.h"
#include "nsIMessage.h"

#include "nsIMsgStatusFeedback.h"
#include "nsMsgRDFUtils.h"

// compose
#include "nsMsgCompCID.h"
#include "nsMsgI18N.h"

// draft/folders/sendlater/etc
#include "nsIMsgCopyService.h"
#include "nsIMsgCopyServiceListener.h"
#include "nsIMsgSendLater.h" 
#include "nsIMsgSendLaterListener.h"
#include "nsIMsgDraft.h"
#include "nsIUrlListener.h"

// undo
#include "nsITransaction.h"
#include "nsMsgTxn.h"

// charset conversions
#include "nsMsgMimeCID.h"
#include "nsIMimeConverter.h"

// Printing
#include "nsMsgPrintEngine.h"

// Save As
#include "nsIFilePicker.h"
#include "nsIStringBundle.h"
#include "nsINetSupportDialogService.h"

// Find / Find Again 
#include "nsIFindComponent.h"

static NS_DEFINE_CID(kIStreamConverterServiceCID, NS_STREAMCONVERTERSERVICE_CID);
static NS_DEFINE_CID(kCMsgMailSessionCID, NS_MSGMAILSESSION_CID); 
static NS_DEFINE_CID(kRDFServiceCID,	NS_RDFSERVICE_CID);
static NS_DEFINE_CID(kMsgSendLaterCID, NS_MSGSENDLATER_CID); 
static NS_DEFINE_CID(kMsgCopyServiceCID,		NS_MSGCOPYSERVICE_CID);
static NS_DEFINE_CID(kMsgPrintEngineCID,		NS_MSG_PRINTENGINE_CID);
static NS_DEFINE_CID(kNetSupportDialogCID, NS_NETSUPPORTDIALOG_CID);


/* This is the next generation string retrieval call */
static NS_DEFINE_CID(kStringBundleServiceCID, NS_STRINGBUNDLESERVICE_CID);

#if defined(DEBUG_seth_) || defined(DEBUG_sspitzer_) || defined(DEBUG_jefft)
#define DEBUG_MESSENGER
#endif

#define FOUR_K 4096

//
// Convert an nsString buffer to plain text...
//
#include "nsIParser.h"
#include "nsParserCIID.h"
#include "nsICharsetConverterManager.h"
#include "nsIContentSink.h"
#include "nsIHTMLToTextSink.h"

static NS_DEFINE_CID(kCParserCID, NS_PARSER_IID);

static nsresult
ConvertBufToPlainText(nsString &aConBuf)
{
  nsresult    rv;
  nsAutoString    convertedText;
  nsCOMPtr<nsIParser> parser;

  if (aConBuf.IsEmpty())
    return NS_OK;

  rv = nsComponentManager::CreateInstance(kCParserCID, nsnull, 
                                          NS_GET_IID(nsIParser), getter_AddRefs(parser));
  if (NS_SUCCEEDED(rv) && parser)
  {
    nsCOMPtr<nsIContentSink> sink;

    sink = do_CreateInstance(NS_PLAINTEXTSINK_CONTRACTID);
    NS_ENSURE_TRUE(sink, NS_ERROR_FAILURE);

    nsCOMPtr<nsIHTMLToTextSink> textSink(do_QueryInterface(sink));
    NS_ENSURE_TRUE(textSink, NS_ERROR_FAILURE);

    textSink->Initialize(&convertedText, 0, 72);

    parser->SetContentSink(sink);

    nsAutoString mimeStr; mimeStr.AppendWithConversion("text/html");
    parser->Parse(aConBuf, 0, mimeStr, PR_FALSE, PR_TRUE);

    //
    // Now if we get here, we need to get from ASCII text to 
    // UTF-8 format or there is a problem downstream...
    //
    if (NS_SUCCEEDED(rv))
    {
      aConBuf = convertedText;
    }
  }

  return rv;
}

// ***************************************************
// jefft - this is a rather obscured class serves for Save Message As File,
// Save Message As Template, and Save Attachment to a file
// 
class nsSaveAllAttachmentsState;

class nsSaveMsgListener : public nsIUrlListener,
                          public nsIMsgCopyServiceListener,
                          public nsIStreamListener
{
public:
    nsSaveMsgListener(nsIFileSpec* fileSpec, nsMessenger* aMessenger);
    virtual ~nsSaveMsgListener();

    NS_DECL_ISUPPORTS

    NS_DECL_NSIURLLISTENER
    NS_DECL_NSIMSGCOPYSERVICELISTENER
    NS_DECL_NSISTREAMLISTENER
    NS_DECL_NSISTREAMOBSERVER

    nsCOMPtr<nsIFileSpec> m_fileSpec;
    nsCOMPtr<nsIOutputStream> m_outputStream;
    char *m_dataBuffer;
    nsCOMPtr<nsIChannel> m_channel;
    nsXPIDLCString m_templateUri;
    nsMessenger *m_messenger; // not ref counted
    nsSaveAllAttachmentsState *m_saveAllAttachmentsState;

    // rhp: For character set handling
    PRBool        m_doCharsetConversion;
    nsString      m_charset;
    nsString      m_outputFormat;
    nsString      m_msgBuffer;
};

class nsSaveAllAttachmentsState
{
public:
    nsSaveAllAttachmentsState(PRUint32 count, const char **urlArray,
                              const char **displayNameArray,
                              const char **messageUriArray,
                              const char *directoryName);
    virtual ~nsSaveAllAttachmentsState();

    PRUint32 m_count;
    PRUint32 m_curIndex;
    char* m_directoryName;
    char** m_urlArray;
    char** m_displayNameArray;
    char** m_messageUriArray;
};

//
// nsMessenger
//
nsMessenger::nsMessenger() 
{
	NS_INIT_REFCNT();
	mScriptObject = nsnull;
	mWindow = nsnull;
  mMsgWindow = nsnull;
  mCharsetInitialized = PR_FALSE;
  mStringBundle = nsnull;

  //	InitializeFolderRoot();
}

nsMessenger::~nsMessenger()
{
    NS_IF_RELEASE(mWindow);

    // Release search context.
    mSearchContext = null_nsCOMPtr();
}


NS_IMPL_ISUPPORTS1(nsMessenger, nsIMessenger)

NS_IMETHODIMP    
nsMessenger::SetWindow(nsIDOMWindowInternal *aWin, nsIMsgWindow *aMsgWindow)
{
	if(!aWin)
	{
		if (mMsgWindow)
		{
			nsCOMPtr<nsIMsgStatusFeedback> aStatusFeedback;

			mMsgWindow->GetStatusFeedback(getter_AddRefs(aStatusFeedback));
			if (aStatusFeedback)
				aStatusFeedback->SetDocShell(nsnull, nsnull);
		}
    // it isn't an error to pass in null for aWin, in fact it means we are shutting
    // down and we should start cleaning things up...
		return NS_OK;
	}

  mMsgWindow = aMsgWindow;

  nsAutoString  docShellName; docShellName.AssignWithConversion("messagepane");
  NS_IF_RELEASE(mWindow);
  mWindow = aWin;
  NS_ADDREF(aWin);

  nsCOMPtr<nsIScriptGlobalObject> globalObj( do_QueryInterface(aWin) );
  NS_ENSURE_TRUE(globalObj, NS_ERROR_FAILURE);

  nsCOMPtr<nsIDocShell> docShell;
  globalObj->GetDocShell(getter_AddRefs(docShell));
  nsCOMPtr<nsIDocShellTreeItem> docShellAsItem(do_QueryInterface(docShell));
  NS_ENSURE_TRUE(docShellAsItem, NS_ERROR_FAILURE);

  nsCOMPtr<nsIDocShellTreeItem> rootDocShellAsItem;
  docShellAsItem->GetSameTypeRootTreeItem(getter_AddRefs(rootDocShellAsItem));

  nsCOMPtr<nsIDocShellTreeNode> 
                     rootDocShellAsNode(do_QueryInterface(rootDocShellAsItem));
  if (rootDocShellAsNode) 
  {
    nsCOMPtr<nsIDocShellTreeItem> childAsItem;
    nsresult rv = rootDocShellAsNode->FindChildWithName(docShellName.GetUnicode(),
      PR_TRUE, PR_FALSE, nsnull, getter_AddRefs(childAsItem));

    mDocShell = do_QueryInterface(childAsItem);

    if (NS_SUCCEEDED(rv) && mDocShell) {

        if (aMsgWindow) {
            nsCOMPtr<nsIMsgStatusFeedback> aStatusFeedback;
            
            aMsgWindow->GetStatusFeedback(getter_AddRefs(aStatusFeedback));
            m_docLoaderObserver = do_QueryInterface(aStatusFeedback);
            if (aStatusFeedback)
            {
                aStatusFeedback->SetDocShell(mDocShell, mWindow);
            }
            mDocShell->SetDocLoaderObserver(m_docLoaderObserver);
            aMsgWindow->GetTransactionManager(getter_AddRefs(mTxnMgr));
        }
    }
  }


  return NS_OK;
}

void
nsMessenger::InitializeDisplayCharset()
{
  if (mCharsetInitialized)
    return;

  // libmime always converts to UTF-8 (both HTML and XML)
  if (mDocShell) 
  {
    nsAutoString aForceCharacterSet; aForceCharacterSet.AssignWithConversion("UTF-8");
    nsCOMPtr<nsIContentViewer> cv;
    mDocShell->GetContentViewer(getter_AddRefs(cv));
    if (cv) 
    {
      nsCOMPtr<nsIMarkupDocumentViewer> muDV = do_QueryInterface(cv);
      if (muDV) {
        muDV->SetForceCharacterSet(aForceCharacterSet.GetUnicode());
      }

      mCharsetInitialized = PR_TRUE;
    }
  }
}


nsresult
nsMessenger::PromptIfFileExists(nsFileSpec &fileSpec)
{
    nsresult rv = NS_ERROR_FAILURE;
    if (fileSpec.Exists())
    {
        nsCOMPtr<nsIPrompt> dialog(do_GetInterface(mDocShell));
        if (!dialog) return rv;
        nsString path;
        PRBool dialogResult = PR_FALSE;
        nsXPIDLString errorMessage;

        fileSpec.GetNativePathString(path);
        const PRUnichar *pathFormatStrings[] = { path.GetUnicode() };
        NS_NAMED_LITERAL_STRING(fileExistsPropertyTag, "fileExists");
        const PRUnichar *fpropertyTag = fileExistsPropertyTag.get();
        if (!mStringBundle)
        {
            rv = InitStringBundle();
            if (NS_FAILED(rv)) return rv;
        }
        rv = mStringBundle->FormatStringFromName(fpropertyTag,
                                                 pathFormatStrings, 1,
                                                 getter_Copies(errorMessage));
        if (NS_FAILED(rv)) return rv;
        rv = dialog->Confirm(nsnull, errorMessage, &dialogResult);
        if (NS_FAILED(rv)) return rv;

        if (dialogResult)
        {
            return NS_OK; // user says okay to replace
        }
        else
        {
            PRInt16 dialogReturn;
            nsCOMPtr<nsIFilePicker> filePicker =
                do_CreateInstance("@mozilla.org/filepicker;1", &rv);
            if (NS_FAILED(rv)) return rv;
            NS_NAMED_LITERAL_STRING(saveAttachmentTag, "Save Attachment");
            const PRUnichar *spropertyTag = saveAttachmentTag.get();
            filePicker->Init(nsnull, spropertyTag, nsIFilePicker::modeSave);
            filePicker->SetDefaultString(path.GetUnicode());
            filePicker->AppendFilters(nsIFilePicker::filterAll);
            filePicker->Show(&dialogReturn);
            if (dialogReturn == nsIFilePicker::returnCancel)
                return NS_ERROR_FAILURE;
            nsCOMPtr<nsILocalFile> localFile;
            nsXPIDLCString filePath;
            rv = filePicker->GetFile(getter_AddRefs(localFile));
            if (NS_FAILED(rv)) return rv;
            rv = localFile->GetPath(getter_Copies(filePath));
            if (NS_FAILED(rv)) return rv;
            fileSpec = (const char*) filePath;
            return NS_OK;
        }
    }
    else
    {
        return NS_OK;
    }
    return rv;
}

nsresult
nsMessenger::InitializeSearch( nsIFindComponent *finder )
{
    nsresult rv = NS_OK;
    if (!finder) return NS_ERROR_NULL_POINTER;

    if (!mSearchContext )
    {
        nsCOMPtr<nsIInterfaceRequestor> docShellIR = do_QueryInterface(mDocShell);
        if (!docShellIR) return NS_ERROR_FAILURE;
        
        nsCOMPtr<nsIDOMWindowInternal> domWindow;
        docShellIR->GetInterface(NS_GET_IID(nsIDOMWindowInternal), getter_AddRefs(domWindow));
        if (!domWindow) return NS_ERROR_FAILURE;
        
        // we need to get the nsIDOMWindowInternal for mWebShell
        // Create the search context for this browser window.
        rv = finder->CreateContext(domWindow, nsnull, getter_AddRefs(mSearchContext));
    }

    return rv;
}


NS_IMETHODIMP
nsMessenger::Find()
{
    nsresult rv = NS_OK;
    PRBool   found = PR_FALSE;

    // Get find component.
    nsCOMPtr <nsIFindComponent> finder = do_GetService(NS_IFINDCOMPONENT_CONTRACTID, &rv);
    if (NS_FAILED(rv)) return rv;
    if (!finder) return NS_ERROR_FAILURE;

    // Make sure we've initialized searching for this document.
    rv = InitializeSearch( finder );
    if (NS_FAILED(rv)) return rv;

    // Perform find via find component.
    if (mSearchContext) {
            rv = finder->Find( mSearchContext, &found );
    }

    return rv;
}

NS_IMETHODIMP
nsMessenger::FindAgain()
{
    nsresult rv = NS_OK;
    PRBool   found = PR_FALSE;

    // Get find component.
    nsCOMPtr <nsIFindComponent> finder = do_GetService(NS_IFINDCOMPONENT_CONTRACTID, &rv);
    if (NS_FAILED(rv)) return rv;
    if (!finder) return NS_ERROR_FAILURE;

    // Make sure we've initialized searching for this document.
    rv = InitializeSearch( finder );
    if (NS_FAILED(rv)) return rv;

    // Perform find via find component.
    if (mSearchContext) {
            rv = finder->FindNext( mSearchContext, &found );
    }

    return rv;
}

NS_IMETHODIMP
nsMessenger::OpenURL(const char * url)
{
  if (url)
  {
#ifdef DEBUG_MESSENGER
    printf("nsMessenger::OpenURL(%s)\n",url);
#endif    

    // This is to setup the display DocShell as UTF-8 capable...
    InitializeDisplayCharset();
    
    char* unescapedUrl = PL_strdup(url);
    if (unescapedUrl)
    {
	  // I don't know why we're unescaping this url - I'll leave it unescaped
	  // for the web shell, but the message service doesn't need it unescaped.
      nsUnescape(unescapedUrl);
      
      nsIMsgMessageService * messageService = nsnull;
      nsresult rv = GetMessageServiceFromURI(url, &messageService);
      
      if (NS_SUCCEEDED(rv) && messageService)
      {
        nsCOMPtr<nsIWebShell> webShell(do_QueryInterface(mDocShell));
        messageService->DisplayMessage(url, webShell, mMsgWindow, nsnull, nsnull, nsnull);
        ReleaseMessageServiceFromURI(url, messageService);
        mLastDisplayURI = url; // remember the last uri we displayed....
      }
      //If it's not something we know about, then just load the url.
      else
      {
        nsAutoString urlStr; urlStr.AssignWithConversion(unescapedUrl);
        nsCOMPtr<nsIWebNavigation> webNav(do_QueryInterface(mDocShell));
        if(webNav)
          webNav->LoadURI(urlStr.GetUnicode(), nsIWebNavigation::LOAD_FLAGS_NONE);
      }
      PL_strfree(unescapedUrl);
    }
    else
    {
      return NS_ERROR_OUT_OF_MEMORY;
    }
  }
  return NS_OK;
}

nsresult
nsMessenger::SaveAttachment(nsIFileSpec * fileSpec,
                            const char * unescapedUrl,
                            const char * messageUri,
                            void *closure)
{
  nsIMsgMessageService * messageService = nsnull;
  nsSaveMsgListener *aListener = nsnull;
  nsSaveAllAttachmentsState *saveState= (nsSaveAllAttachmentsState*) closure;
  nsAutoString from, to;
  nsCOMPtr<nsISupports> channelSupport;
  nsCOMPtr<nsIStreamListener> convertedListener;
  nsCOMPtr<nsIMsgMessageFetchPartService> fetchService;
  nsAutoString urlString;
  char *urlCString = nsnull;
  nsCOMPtr<nsIURI> aURL;
  nsCAutoString fullMessageUri(messageUri);
  nsresult rv = NS_OK;
  
  NS_WITH_SERVICE(nsIStreamConverterService,
                  streamConverterService,  
                  kIStreamConverterServiceCID, &rv);
  if (NS_FAILED(rv)) goto done;

  aListener = new nsSaveMsgListener(fileSpec, this);
  if (!aListener)
  {
      rv = NS_ERROR_OUT_OF_MEMORY;
      goto done;
  }
  NS_ADDREF(aListener);

  if (saveState)
      aListener->m_saveAllAttachmentsState = saveState;

  urlString.AssignWithConversion(unescapedUrl);

  urlString.ReplaceSubstring(NS_ConvertASCIItoUCS2("/;section"), NS_ConvertASCIItoUCS2("?section"));
  urlCString = urlString.ToNewCString();

  rv = CreateStartupUrl(urlCString, getter_AddRefs(aURL));
  nsCRT::free(urlCString);

  if (NS_FAILED(rv)) goto done;

  rv = GetMessageServiceFromURI(messageUri, &messageService);
  if (NS_FAILED(rv)) goto done;

  fetchService = do_QueryInterface(messageService);
  // if the message service has a fetch part service then we know we can fetch mime parts...
  if (fetchService)
  {
    PRInt32 sectionPos = urlString.Find("?section");
    nsString mimePart;

    urlString.Right(mimePart, urlString.Length() - sectionPos);
    fullMessageUri.AppendWithConversion(mimePart);
   
    messageUri = fullMessageUri.GetBuffer();
  }
  {
    aListener->m_channel = null_nsCOMPtr();
    rv = NS_NewInputStreamChannel(getter_AddRefs(aListener->m_channel),
                                  aURL,
                                  nsnull,      // inputStream
                                  nsnull,      // contentType
                                  -1);
    if (NS_FAILED(rv)) goto done;

    from.AssignWithConversion(MESSAGE_RFC822);
    to.AssignWithConversion("text/xul");
  
    channelSupport = do_QueryInterface(aListener->m_channel);

    rv = streamConverterService->AsyncConvertData(
        from.GetUnicode(), to.GetUnicode(), aListener,
        channelSupport, getter_AddRefs(convertedListener));
    if (NS_FAILED(rv)) goto done;

    if (fetchService)
      rv = fetchService->FetchMimePart(aURL, messageUri, convertedListener,
                                          mMsgWindow, nsnull,nsnull);
    else
      rv = messageService->DisplayMessage(messageUri,
                                        convertedListener,mMsgWindow,
                                        nsnull, nsnull, nsnull); 
  }

done:
    if (messageService)
      ReleaseMessageServiceFromURI(unescapedUrl, messageService);

    if (NS_FAILED(rv))
    {
        NS_IF_RELEASE(aListener);
        Alert("saveAttachmentFailed");
    }
	return rv;
}

NS_IMETHODIMP
nsMessenger::OpenAttachment(const char * aContentType, const char * aUrl, const
                            char * aDisplayName, const char * aMessageUri)
{
  nsresult rv = NS_OK;
  nsIMsgMessageService * messageService = nsnull;
  rv = GetMessageServiceFromURI(aMessageUri, &messageService);
  if (messageService)
  {
    rv = messageService->OpenAttachment(aContentType, aDisplayName, aUrl, aMessageUri, mDocShell, mMsgWindow, nsnull);
  }
  if (messageService)
     ReleaseMessageServiceFromURI(aMessageUri, messageService);
	return rv;
}

NS_IMETHODIMP
nsMessenger::SaveAttachment(const char * url, const char * displayName, 
                            const char * messageUri)
{
  nsresult rv = NS_ERROR_OUT_OF_MEMORY;
  char *unescapedUrl = nsnull;
  nsCOMPtr<nsIFilePicker> filePicker =
      do_CreateInstance("@mozilla.org/filepicker;1", &rv);
  char * unescapedDisplayName = nsnull;
  nsAutoString tempStr;
  PRInt16 dialogResult;
  nsCOMPtr<nsILocalFile> localFile;
  nsCOMPtr<nsIFileSpec> fileSpec;
  nsXPIDLCString filePath;

  if (NS_FAILED(rv)) goto done;
  if (!url) goto done;

#ifdef DEBUG_MESSENGER
  printf("nsMessenger::SaveAttachment(%s)\n",url);
#endif    
  unescapedUrl = PL_strdup(url);
  if (!unescapedUrl) goto done;

  nsUnescape(unescapedUrl);
  
  unescapedDisplayName = nsCRT::strdup(displayName);
  if (!unescapedDisplayName) goto done;
  nsUnescape(unescapedDisplayName);
    
  /* we need to convert the UTF-8 fileName to platform specific character set.
     The display name is in UTF-8 because it has been escaped from JS
  */ 
  
  rv = ConvertToUnicode(NS_ConvertASCIItoUCS2("UTF-8"), unescapedDisplayName, tempStr);
  if (NS_SUCCEEDED(rv))
  {
      filePicker->Init(
          nsnull, 
          GetString(NS_ConvertASCIItoUCS2("Save Attachment").GetUnicode()),
          nsIFilePicker::modeSave
          );
      filePicker->SetDefaultString(tempStr.GetUnicode());
      filePicker->AppendFilters(nsIFilePicker::filterAll);
  }      
  nsCRT::free(unescapedDisplayName);
  
  filePicker->Show(&dialogResult);
  if (dialogResult == nsIFilePicker::returnCancel)
      goto done;

  rv = filePicker->GetFile(getter_AddRefs(localFile));
  if (NS_FAILED(rv)) goto done;
  
  rv = localFile->GetPath(getter_Copies(filePath));
  fileSpec = do_CreateInstance("@mozilla.org/filespec;1", &rv);
  if (NS_FAILED(rv)) goto done;
  fileSpec->SetNativePath(filePath);
  rv = SaveAttachment(fileSpec, unescapedUrl, messageUri, nsnull);

done:
    PR_FREEIF(unescapedUrl);
    return rv;
}


NS_IMETHODIMP
nsMessenger::SaveAllAttachments(PRUint32 count, const char **urlArray,
                                const char **displayNameArray,
                                const char **messageUriArray)
{
    nsresult rv = NS_ERROR_OUT_OF_MEMORY;
    nsCOMPtr<nsIFilePicker> filePicker =
        do_CreateInstance("@mozilla.org/filepicker;1", &rv);
    nsCOMPtr<nsILocalFile> localFile;
    nsCOMPtr<nsIFileSpec> fileSpec;
    nsXPIDLCString dirName;
    char *unescapedUrl = nsnull, *unescapedName = nsnull, *tempCStr = nsnull;
    nsAutoString tempStr;
    nsSaveAllAttachmentsState *saveState = nsnull;
    PRInt16 dialogResult;

    if (NS_FAILED(rv)) goto done;
    filePicker->Init(
        nsnull, 
        GetString(NS_ConvertASCIItoUCS2("Save All Attachments").GetUnicode()),
        nsIFilePicker::modeGetFolder
        );
    filePicker->Show(&dialogResult);
    if (dialogResult == nsIFilePicker::returnCancel)
        goto done;
    rv = filePicker->GetFile(getter_AddRefs(localFile));
    if (NS_FAILED(rv)) goto done;
    rv = localFile->GetPath(getter_Copies(dirName));
    if (NS_FAILED(rv)) goto done;
    rv = NS_NewFileSpec(getter_AddRefs(fileSpec));
    if (NS_FAILED(rv)) goto done;

    saveState = new nsSaveAllAttachmentsState(count, urlArray,
                                              displayNameArray,
                                              messageUriArray, 
                                              (const char*) dirName);
    {
        nsFileSpec aFileSpec((const char *) dirName);
        unescapedUrl = PL_strdup(urlArray[0]);
        nsUnescape(unescapedUrl);
        unescapedName = PL_strdup(displayNameArray[0]);
        nsUnescape(unescapedName);
        rv = ConvertToUnicode(NS_ConvertASCIItoUCS2("UTF-8"), unescapedName, tempStr);
        if (NS_FAILED(rv)) goto done;
        rv = ConvertFromUnicode(nsMsgI18NFileSystemCharset(), tempStr,
                                &tempCStr);
        if (NS_FAILED(rv)) goto done;
        PR_FREEIF(unescapedName);
        unescapedName = tempCStr;
        aFileSpec += unescapedName;
        rv = PromptIfFileExists(aFileSpec);
        if (NS_FAILED(rv)) return rv;
        fileSpec->SetFromFileSpec(aFileSpec);
        rv = SaveAttachment(fileSpec, unescapedUrl, messageUriArray[0], 
                            (void *)saveState);
        if (NS_FAILED(rv)) goto done;
    }
done:

    PR_FREEIF (unescapedUrl);
    PR_FREEIF (unescapedName);

    return rv;
}


NS_IMETHODIMP
nsMessenger::SaveAs(const char* url, PRBool asFile, nsIMsgIdentity* identity, nsIMsgWindow *aMsgWindow)
{
    nsresult rv = NS_ERROR_FAILURE;
    nsIMsgMessageService* messageService = nsnull;
    nsAutoString defaultFile(NS_ConvertASCIItoUCS2("mail"));
    nsCOMPtr<nsIUrlListener> urlListener;
    nsSaveMsgListener *aListener = nsnull;
    nsCOMPtr<nsIURI> aURL;
    nsAutoString urlString;
    char *urlCString = nsnull;
    nsCOMPtr<nsISupports> channelSupport;
    nsCOMPtr<nsIStreamListener> convertedListener;
    PRBool needDummyHeader = PR_TRUE;
    PRBool canonicalLineEnding = PR_FALSE;
    PRInt16 saveAsFileType = 0; // 0 - raw, 1 = html, 2 = text;
    
    nsCOMPtr<nsIStreamConverterService> streamConverterService = do_GetService(kIStreamConverterServiceCID, &rv);
    if (NS_FAILED(rv)) goto done;
    
    if (!url) {
        rv = NS_ERROR_NULL_POINTER;
        goto done;
    }

    rv = GetMessageServiceFromURI(url, &messageService);
    if (NS_FAILED(rv)) goto done;

    if (asFile) {

        nsCOMPtr<nsIFilePicker> filePicker = do_CreateInstance("@mozilla.org/filepicker;1", &rv);
        if (NS_FAILED(rv)) goto done;

        filePicker->Init(nsnull, GetString(NS_ConvertASCIItoUCS2("SaveMailAs").GetUnicode()), nsIFilePicker::modeSave);

        filePicker->SetDefaultString(defaultFile.GetUnicode());
        filePicker->AppendFilter(GetString(NS_ConvertASCIItoUCS2("EMLFiles").GetUnicode()),
                                 NS_ConvertASCIItoUCS2("*.eml").GetUnicode());
        filePicker->AppendFilters(nsIFilePicker::filterHTML | nsIFilePicker::filterText | nsIFilePicker::filterAll);

        PRInt16 dialogResult;
        filePicker->Show(&dialogResult);

        if (dialogResult == nsIFilePicker::returnCancel)
            goto done;
            
        nsCOMPtr<nsILocalFile> localFile;
        rv = filePicker->GetFile(getter_AddRefs(localFile));
        if (NS_FAILED(rv)) goto done;
            
        nsXPIDLCString tmpFileName;
        rv = localFile->GetLeafName(getter_Copies(tmpFileName));
        if (NS_FAILED(rv)) goto done;
        nsCAutoString fileName(tmpFileName);
            
        // First, check if they put ANY extension on the file, if not,
        // then we should look at the type of file they have chosen and
        // tack on the file extension for them.
        //
        if (fileName.RFind(".", PR_TRUE) != -1)
        {
            if (fileName.RFind(".htm", PR_TRUE) != -1)
                saveAsFileType = 1;
            else if (fileName.RFind(".txt", PR_TRUE) != -1)
                saveAsFileType = 2;
            else
                saveAsFileType = 0;   // .eml type
        } else {
            saveAsFileType = 0; // .eml type
        }


        // XXX argh!  converting from nsILocalFile to nsFileSpec ... oh baby, lets drop from unicode to ascii too
        //        nsXPIDLString path;
        //        localFile->GetUnicodePath(getter_Copies(path));
        nsXPIDLCString path;
        localFile->GetPath(getter_Copies(path));
        nsCOMPtr<nsIFileSpec> fileSpec = do_CreateInstance("@mozilla.org/filespec;1", &rv);
        if (NS_FAILED(rv)) goto done;
        fileSpec->SetNativePath(path);

        aListener = new nsSaveMsgListener(fileSpec, this);
        if (!aListener) {
            rv = NS_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        
        NS_ADDREF(aListener);

        rv = aListener->QueryInterface(NS_GET_IID(nsIUrlListener),
                                       getter_AddRefs(urlListener));
        if (NS_FAILED(rv)) goto done;
        
        switch (saveAsFileType) {
        case 0:
        default:
            rv = messageService->SaveMessageToDisk(url, fileSpec, PR_TRUE,
                                                   urlListener, nsnull,
                                                   PR_FALSE, mMsgWindow);
            break;
        case 1:
        case 2:
            urlString.AssignWithConversion(url);

            // Setup the URL for a "Save As..." Operation...
            // For now, if this is a save as TEXT operation, then do
            // a "printing" operation
            //
            if (saveAsFileType == 1)
                urlString.AppendWithConversion("?header=saveas");
            else
                urlString.AppendWithConversion("?header=print");
            
            urlCString = urlString.ToNewCString();
            rv = CreateStartupUrl(urlCString, getter_AddRefs(aURL));
            nsCRT::free(urlCString);
            if (NS_FAILED(rv)) goto done;

            aListener->m_channel = null_nsCOMPtr();
            rv = NS_NewInputStreamChannel(getter_AddRefs(aListener->m_channel),
                                          aURL, 
                                          nsnull,      // inputStream
                                          nsnull,      // contentType
                                          -1);         // contentLength
            if (NS_FAILED(rv)) goto done;

            aListener->m_outputFormat.AssignWithConversion(saveAsFileType == 1 ? TEXT_HTML : TEXT_PLAIN);
            
            // Mark the fact that we need to do charset handling/text conversion!
            if (aListener->m_outputFormat.EqualsWithConversion(TEXT_PLAIN))
                aListener->m_doCharsetConversion = PR_TRUE;
            
            channelSupport = do_QueryInterface(aListener->m_channel);
            
            rv = streamConverterService->AsyncConvertData(NS_ConvertASCIItoUCS2(MESSAGE_RFC822).GetUnicode(),
            // RICHIE - we should be able to go RFC822 to TXT, but not until
            // Bug #1775 is fixed. aListener->m_outputFormat.GetUnicode() 
                                                          NS_ConvertASCIItoUCS2(TEXT_HTML).GetUnicode(), 
                                                          aListener,
                                                          channelSupport,
                                                          getter_AddRefs(convertedListener));
            if (NS_FAILED(rv)) goto done;

            rv = messageService->DisplayMessage(url, convertedListener,mMsgWindow,
                                                nsnull, nsnull, nsnull);
            break;
        }

    }
    else
    {
        // ** save as Template
        nsCOMPtr<nsIFileSpec> fileSpec;
        nsFileSpec tmpFileSpec("nsmail.tmp");
        rv = NS_NewFileSpecWithSpec(tmpFileSpec, getter_AddRefs(fileSpec));
        if (NS_FAILED(rv)) goto done;

        aListener = new nsSaveMsgListener(fileSpec, this);
        if (!aListener) {
            rv = NS_ERROR_OUT_OF_MEMORY;
            goto done;
        }
        
        NS_ADDREF(aListener);

        if (identity)
            rv = identity->GetStationeryFolder(getter_Copies(aListener->m_templateUri));
        if (NS_FAILED(rv)) goto done;

        needDummyHeader =
            PL_strcasestr(aListener->m_templateUri, "mailbox://") 
            != nsnull;
        canonicalLineEnding =
            PL_strcasestr(aListener->m_templateUri, "imap://")
            != nsnull;
        rv = aListener->QueryInterface(
                                       NS_GET_IID(nsIUrlListener),
                                       getter_AddRefs(urlListener));
        if (NS_FAILED(rv)) goto done;

        rv = messageService->SaveMessageToDisk(url, fileSpec, 
                                               needDummyHeader,
                                               urlListener, nsnull,
                                               canonicalLineEnding, mMsgWindow); 
    }
done:
    if (messageService)
        ReleaseMessageServiceFromURI(url, messageService);

    if (NS_FAILED(rv)) {
        NS_IF_RELEASE(aListener);
        Alert("saveMessageFailed");
    }
	return rv;
}

nsresult
nsMessenger::Alert(const char *stringName)
{
    nsresult rv = NS_OK;
    nsString errorMessage(GetString(NS_ConvertASCIItoUCS2(stringName).get()));
    if (mDocShell)
    {
        nsCOMPtr<nsIPrompt> dialog(do_GetInterface(mDocShell));
        
        if (dialog) {
            rv = dialog->Alert(nsnull, errorMessage.GetUnicode());
        }
    }
    return rv;
}

nsresult
nsMessenger::DoCommand(nsIRDFCompositeDataSource* db, char *command,
                       nsISupportsArray *srcArray, 
                       nsISupportsArray *argumentArray)
{

	nsresult rv;

    NS_WITH_SERVICE(nsIRDFService, rdfService, kRDFServiceCID, &rv);
	if(NS_FAILED(rv))
		return rv;

	nsCOMPtr<nsIRDFResource> commandResource;
	rv = rdfService->GetResource(command, getter_AddRefs(commandResource));
	if(NS_SUCCEEDED(rv))
	{
		rv = db->DoCommand(srcArray, commandResource, argumentArray);
	}

	return rv;

}

NS_IMETHODIMP
nsMessenger::DeleteMessages(nsIRDFCompositeDataSource *database,
                            nsIRDFResource *srcFolderResource,
                            nsISupportsArray *resourceArray,
							PRBool reallyDelete)
{
	nsresult rv;

	if(!database || !srcFolderResource || !resourceArray)
		return NS_ERROR_NULL_POINTER;

	nsCOMPtr<nsISupportsArray> folderArray;

	rv = NS_NewISupportsArray(getter_AddRefs(folderArray));
	if(NS_FAILED(rv))
	{
		return NS_ERROR_OUT_OF_MEMORY;
	}

	folderArray->AppendElement(srcFolderResource);
	
	if(reallyDelete)
		rv = DoCommand(database, NC_RDF_REALLY_DELETE, folderArray, resourceArray);
	else
		rv = DoCommand(database, NC_RDF_DELETE, folderArray, resourceArray);


	return rv;
}

NS_IMETHODIMP nsMessenger::DeleteFolders(nsIRDFCompositeDataSource *db,
                                         nsIRDFResource *parentResource,
                                         nsIRDFResource *deletedFolderResource)
{
	nsresult rv;

	if(!db || !parentResource || !deletedFolderResource)
		return NS_ERROR_NULL_POINTER;

	nsCOMPtr<nsISupportsArray> parentArray, deletedArray;

	rv = NS_NewISupportsArray(getter_AddRefs(parentArray));

	if(NS_FAILED(rv))
	{
		return NS_ERROR_OUT_OF_MEMORY;
	}

	rv = NS_NewISupportsArray(getter_AddRefs(deletedArray));

	if(NS_FAILED(rv))
	{
		return NS_ERROR_OUT_OF_MEMORY;
	}

	parentArray->AppendElement(parentResource);
	deletedArray->AppendElement(deletedFolderResource);

	rv = DoCommand(db, NC_RDF_DELETE, parentArray, deletedArray);

	return NS_OK;
}

NS_IMETHODIMP
nsMessenger::CopyMessages(nsIRDFCompositeDataSource *database,
                          nsIRDFResource *srcResource, // folder
						  nsIRDFResource *dstResource,
                          nsISupportsArray *argumentArray, // nsIMessages
                          PRBool isMove)
{
	nsresult rv;

	if(!srcResource || !dstResource || !argumentArray)
		return NS_ERROR_NULL_POINTER;

	nsCOMPtr<nsIMsgFolder> srcFolder;
	nsCOMPtr<nsISupportsArray> folderArray;
    
	srcFolder = do_QueryInterface(srcResource);
	if(!srcFolder)
		return NS_ERROR_NO_INTERFACE;

	nsCOMPtr<nsISupports> srcFolderSupports(do_QueryInterface(srcFolder));
	if(srcFolderSupports)
		argumentArray->InsertElementAt(srcFolderSupports, 0);

	rv = NS_NewISupportsArray(getter_AddRefs(folderArray));
	if(NS_FAILED(rv))
	{
		return NS_ERROR_OUT_OF_MEMORY;
	}

	folderArray->AppendElement(dstResource);
	
	rv = DoCommand(database, isMove ? (char *)NC_RDF_MOVE : (char *)NC_RDF_COPY, folderArray, argumentArray);
	return rv;

}


NS_IMETHODIMP
nsMessenger::CopyFolders(nsIRDFCompositeDataSource *database,
                          nsIRDFResource *dstResource,
                          nsISupportsArray *argumentArray, // nsIFolders
                          PRBool isMoveFolder)
{
	nsresult rv;

	if(!dstResource || !argumentArray)
		return NS_ERROR_NULL_POINTER;

	nsCOMPtr<nsISupportsArray> folderArray;
    
	rv = NS_NewISupportsArray(getter_AddRefs(folderArray));

	NS_ENSURE_SUCCESS(rv,rv);

	folderArray->AppendElement(dstResource);
	
	return DoCommand(database, isMoveFolder ? (char *)NC_RDF_MOVEFOLDER : (char *)NC_RDF_COPYFOLDER, folderArray, argumentArray);
	
}

NS_IMETHODIMP
nsMessenger::RenameFolder(nsIRDFCompositeDataSource* db,
                          nsIRDFResource* folderResource,
                          const PRUnichar* name)
{
  nsresult rv = NS_ERROR_NULL_POINTER;
  if (!db || !folderResource || !name || !*name) return rv;
    nsCOMPtr<nsISupportsArray> folderArray;
    nsCOMPtr<nsISupportsArray> argsArray;

  rv = NS_NewISupportsArray(getter_AddRefs(folderArray));
  if (NS_FAILED(rv)) return rv;
  folderArray->AppendElement(folderResource);
  rv = NS_NewISupportsArray(getter_AddRefs(argsArray));
  if (NS_FAILED(rv)) return rv;
  NS_WITH_SERVICE(nsIRDFService, rdfService, kRDFServiceCID, &rv);
  if(NS_SUCCEEDED(rv))
  {
    nsCOMPtr<nsIRDFLiteral> nameLiteral;

    rdfService->GetLiteral(name, getter_AddRefs(nameLiteral));
    argsArray->AppendElement(nameLiteral);
    rv = DoCommand(db, NC_RDF_RENAME, folderArray, argsArray);
  }
  return rv;
}

NS_IMETHODIMP
nsMessenger::CompactFolder(nsIRDFCompositeDataSource* db,
                           nsIRDFResource* folderResource, PRBool forAll)
{
  nsresult rv = NS_ERROR_NULL_POINTER;
  
  if (!db || !folderResource) return rv;
  nsCOMPtr<nsISupportsArray> folderArray;

  rv = NS_NewISupportsArray(getter_AddRefs(folderArray));
  if (NS_FAILED(rv)) return rv;
  folderArray->AppendElement(folderResource);
  rv = DoCommand(db, NS_CONST_CAST(char*, forAll ? NC_RDF_COMPACTALL : NC_RDF_COMPACT),  folderArray, nsnull);
  if (NS_SUCCEEDED(rv) && mTxnMgr)
      mTxnMgr->Clear();
  return rv;
}

NS_IMETHODIMP
nsMessenger::EmptyTrash(nsIRDFCompositeDataSource* db,
                        nsIRDFResource* folderResource)
{
  nsresult rv = NS_ERROR_NULL_POINTER;
  
  if (!db || !folderResource) return rv;
  nsCOMPtr<nsISupportsArray> folderArray;

  rv = NS_NewISupportsArray(getter_AddRefs(folderArray));
  if (NS_FAILED(rv)) return rv;
  folderArray->AppendElement(folderResource);
  rv = DoCommand(db, NC_RDF_EMPTYTRASH, folderArray, nsnull);
  if (NS_SUCCEEDED(rv) && mTxnMgr)
      mTxnMgr->Clear();
  return rv;
}

NS_IMETHODIMP nsMessenger::GetUndoTransactionType(PRUint32 *txnType)
{
    nsresult rv = NS_ERROR_NULL_POINTER;
    if (!txnType || !mTxnMgr)
        return rv;
    *txnType = nsMessenger::eUnknown;
    nsITransaction *txn = nsnull;
    // ** jt -- too bad PeekUndoStack not AddRef'ing
    rv = mTxnMgr->PeekUndoStack(&txn);
    if (NS_SUCCEEDED(rv) && txn)
    {
        nsCOMPtr<nsMsgTxn> msgTxn = do_QueryInterface(txn, &rv);
        if (NS_SUCCEEDED(rv) && msgTxn)
            rv = msgTxn->GetTransactionType(txnType);
    }
    return rv;
}

NS_IMETHODIMP nsMessenger::CanUndo(PRBool *bValue)
{
    nsresult rv = NS_ERROR_NULL_POINTER;
    if (!bValue || !mTxnMgr)
        return rv;
    *bValue = PR_FALSE;
    PRInt32 count = 0;
    rv = mTxnMgr->GetNumberOfUndoItems(&count);
    if (NS_SUCCEEDED(rv) && count > 0)
        *bValue = PR_TRUE;
    return rv;
}

NS_IMETHODIMP nsMessenger::GetRedoTransactionType(PRUint32 *txnType)
{
    nsresult rv = NS_ERROR_NULL_POINTER;
    if (!txnType || !mTxnMgr)
        return rv;
    *txnType = nsMessenger::eUnknown;
    nsITransaction *txn = nsnull;
    // ** jt - too bad PeekRedoStack not AddRef'ing
    rv = mTxnMgr->PeekRedoStack(&txn);
    if (NS_SUCCEEDED(rv) && txn)
    {
        nsCOMPtr<nsMsgTxn> msgTxn = do_QueryInterface(txn, &rv);
        if (NS_SUCCEEDED(rv) && msgTxn)
            rv = msgTxn->GetTransactionType(txnType);
    }
    return rv;
}

NS_IMETHODIMP nsMessenger::CanRedo(PRBool *bValue)
{
    nsresult rv = NS_ERROR_NULL_POINTER;
    if (!bValue || !mTxnMgr)
        return rv;
    *bValue = PR_FALSE;
    PRInt32 count = 0;
    rv = mTxnMgr->GetNumberOfRedoItems(&count);
    if (NS_SUCCEEDED(rv) && count > 0)
        *bValue = PR_TRUE;
    return rv;
}

NS_IMETHODIMP
nsMessenger::Undo(nsIMsgWindow *msgWindow)
{
  nsresult rv = NS_OK;
  if (mTxnMgr)
  {
    PRInt32 numTxn = 0;
    rv = mTxnMgr->GetNumberOfUndoItems(&numTxn);
    if (NS_SUCCEEDED(rv) && numTxn > 0)
    {
        nsITransaction *txn = nsnull;
        // ** jt -- PeekUndoStack not AddRef'ing
        rv = mTxnMgr->PeekUndoStack(&txn);
        if (NS_SUCCEEDED(rv) && txn)
        {
            nsCOMPtr<nsMsgTxn> msgTxn = do_QueryInterface(txn, &rv);
            if (NS_SUCCEEDED(rv) && msgTxn)
                msgTxn->SetMsgWindow(msgWindow);
        }
        mTxnMgr->Undo();
    }
  }
  return rv;
}

NS_IMETHODIMP
nsMessenger::Redo(nsIMsgWindow *msgWindow)
{
  nsresult rv = NS_OK;
  if (mTxnMgr)
  {
    PRInt32 numTxn = 0;
    rv = mTxnMgr->GetNumberOfRedoItems(&numTxn);
    if (NS_SUCCEEDED(rv) && numTxn > 0)
    {
        nsITransaction *txn = nsnull;
        // jt -- PeekRedoStack not AddRef'ing
        rv = mTxnMgr->PeekRedoStack(&txn);
        if (NS_SUCCEEDED(rv) && txn)
        {
            nsCOMPtr<nsMsgTxn> msgTxn = do_QueryInterface(txn, &rv);
            if (NS_SUCCEEDED(rv) && msgTxn)
                msgTxn->SetMsgWindow(msgWindow);
        }
        mTxnMgr->Redo();
    }
  }
  return rv;
}

NS_IMETHODIMP
nsMessenger::GetTransactionManager(nsITransactionManager* *aTxnMgr)
{
  if (!mTxnMgr || !aTxnMgr)
    return NS_ERROR_NULL_POINTER;

  *aTxnMgr = mTxnMgr;
  NS_ADDREF(*aTxnMgr);

  return NS_OK;
}

NS_IMETHODIMP nsMessenger::SetDocumentCharset(const PRUnichar *characterSet)
{
	// We want to redisplay the currently selected message (if any) but forcing the 
  // redisplay to use characterSet
  if (!mLastDisplayURI.IsEmpty())
  {
    nsIMsgMessageService * messageService = nsnull;
    nsresult rv = GetMessageServiceFromURI(mLastDisplayURI, &messageService);
    
    if (NS_SUCCEEDED(rv) && messageService)
    {
      nsCOMPtr<nsIWebShell> webShell(do_QueryInterface(mDocShell));
      messageService->DisplayMessage(mLastDisplayURI, webShell, mMsgWindow, nsnull, characterSet, nsnull);
      ReleaseMessageServiceFromURI(mLastDisplayURI, messageService);
    }
  }
  
  return NS_OK;
}

////////////////////////////////////////////////////////////////////////////////////
// This is the listener class for the send operation. 
////////////////////////////////////////////////////////////////////////////////////
class SendLaterListener: public nsIMsgSendLaterListener
{
public:
  SendLaterListener(void);
  virtual ~SendLaterListener(void);

  // nsISupports interface
  NS_DECL_ISUPPORTS

  /* void OnStartSending (in PRUint32 aTotalMessageCount); */
  NS_IMETHOD OnStartSending(PRUint32 aTotalMessageCount);

  /* void OnProgress (in PRUint32 aCurrentMessage, in PRUint32 aTotalMessage); */
  NS_IMETHOD OnProgress(PRUint32 aCurrentMessage, PRUint32 aTotalMessage);

  /* void OnStatus (in wstring aMsg); */
  NS_IMETHOD OnStatus(const PRUnichar *aMsg);

  /* void OnStopSending (in nsresult aStatus, in wstring aMsg, in PRUint32 aTotalTried, in PRUint32 aSuccessful); */
  NS_IMETHOD OnStopSending(nsresult aStatus, const PRUnichar *aMsg, PRUint32 aTotalTried, PRUint32 aSuccessful);
};

NS_IMPL_ISUPPORTS1(SendLaterListener, nsIMsgSendLaterListener)

SendLaterListener::SendLaterListener()
{
  NS_INIT_REFCNT();
}

SendLaterListener::~SendLaterListener()
{
}

nsresult
SendLaterListener::OnStartSending(PRUint32 aTotalMessageCount)
{
  return NS_OK;
}

nsresult
SendLaterListener::OnProgress(PRUint32 aCurrentMessage, PRUint32 aTotalMessage)
{
  return NS_OK;
}

nsresult
SendLaterListener::OnStatus(const PRUnichar *aMsg)
{
  return NS_OK;
}

nsresult
SendLaterListener::OnStopSending(nsresult aStatus, const PRUnichar *aMsg, PRUint32 aTotalTried, 
                                 PRUint32 aSuccessful) 
{
#ifdef NS_DEBUG
  if (NS_SUCCEEDED(aStatus))
    printf("SendLaterListener::OnStopSending: Tried to send %d messages. %d successful.\n",
            aTotalTried, aSuccessful);
#endif

  return NS_OK;
}

NS_IMETHODIMP
nsMessenger::SendUnsentMessages(nsIMsgIdentity *aIdentity)
{
	nsresult rv;
	nsCOMPtr<nsIMsgSendLater> pMsgSendLater; 
	rv = nsComponentManager::CreateInstance(kMsgSendLaterCID, NULL,NS_GET_IID(nsIMsgSendLater),
																					(void **)getter_AddRefs(pMsgSendLater)); 
	if (NS_SUCCEEDED(rv) && pMsgSendLater) 
	{ 
#ifdef DEBUG
		printf("We succesfully obtained a nsIMsgSendLater interface....\n"); 
#endif

    SendLaterListener *sendLaterListener = new SendLaterListener();
    if (!sendLaterListener)
        return NS_ERROR_FAILURE;

    NS_ADDREF(sendLaterListener);
    pMsgSendLater->AddListener(sendLaterListener);

    pMsgSendLater->SendUnsentMessages(aIdentity, nsnull); 
    NS_RELEASE(sendLaterListener);
	} 
	return NS_OK;
}

NS_IMETHODIMP nsMessenger::DoPrint()
{
#ifdef DEBUG_MESSENGER
  printf("nsMessenger::DoPrint()\n");
#endif

  nsresult rv = NS_ERROR_FAILURE;

  NS_ENSURE_TRUE(mDocShell, NS_ERROR_FAILURE);

  nsCOMPtr<nsIContentViewer> viewer;
  mDocShell->GetContentViewer(getter_AddRefs(viewer));

  if (viewer) 
  {
    nsCOMPtr<nsIContentViewerFile> viewerFile = do_QueryInterface(viewer);
    if (viewerFile) {
      rv = viewerFile->Print(PR_FALSE,nsnull);
    }
#ifdef DEBUG_MESSENGER
    else {
	    printf("the content viewer does not support printing\n");
    }
#endif
  }
#ifdef DEBUG_MESSENGER
  else {
	printf("failed to get the viewer for printing\n");
  }
#endif
  
  return rv;
}

NS_IMETHODIMP nsMessenger::DoPrintPreview()
{
  nsresult rv = NS_ERROR_NOT_IMPLEMENTED;
#ifdef DEBUG_MESSENGER
  printf("nsMessenger::DoPrintPreview() not implemented yet\n");
#endif
  return rv;  
}

nsSaveMsgListener::nsSaveMsgListener(nsIFileSpec* aSpec, nsMessenger *aMessenger)
{
    NS_INIT_REFCNT();
    if (aSpec)
      m_fileSpec = do_QueryInterface(aSpec);
    m_messenger = aMessenger;
    m_dataBuffer = nsnull;

    // rhp: for charset handling
    m_doCharsetConversion = PR_FALSE;
    m_saveAllAttachmentsState = nsnull;
}

nsSaveMsgListener::~nsSaveMsgListener()
{
}

// 
// nsISupports
//
NS_IMPL_ISUPPORTS3(nsSaveMsgListener, nsIUrlListener, nsIMsgCopyServiceListener, nsIStreamListener)

// 
// nsIUrlListener
// 
NS_IMETHODIMP
nsSaveMsgListener::OnStartRunningUrl(nsIURI* url)
{
    return NS_OK;
}

NS_IMETHODIMP
nsSaveMsgListener::OnStopRunningUrl(nsIURI* url, nsresult exitCode)
{
  nsresult rv = exitCode;
  PRBool killSelf = PR_TRUE;

  if (m_fileSpec)
  {
    m_fileSpec->Flush();
    m_fileSpec->CloseStream();
    if (NS_FAILED(rv)) goto done;
    if (m_templateUri) { // ** save as template goes here
        NS_WITH_SERVICE(nsIRDFService, rdf, kRDFServiceCID, &rv);
        if (NS_FAILED(rv)) goto done;
        nsCOMPtr<nsIRDFResource> res;
        rv = rdf->GetResource(m_templateUri, getter_AddRefs(res));
        if (NS_FAILED(rv)) goto done;
        nsCOMPtr<nsIMsgFolder> templateFolder;
        templateFolder = do_QueryInterface(res, &rv);
        if (NS_FAILED(rv)) goto done;
        NS_WITH_SERVICE(nsIMsgCopyService, copyService, kMsgCopyServiceCID, &rv);
        if (NS_FAILED(rv)) goto done;
        rv = copyService->CopyFileMessage(m_fileSpec, templateFolder, nsnull,
                                          PR_TRUE, this, nsnull);
        killSelf = PR_FALSE;
    }
  }

done:
  if (NS_FAILED(rv))
  {
    if (m_fileSpec)
    {
      nsFileSpec realSpec;
      m_fileSpec->GetFileSpec(&realSpec);
      realSpec.Delete(PR_FALSE);
    }
    if (m_messenger)
    {
        m_messenger->Alert("saveMessageFailed");
    }
  }
  if (killSelf)
      Release(); // no more work needs to be done; kill ourself

  return rv;
}

NS_IMETHODIMP
nsSaveMsgListener::OnStartCopy(void)
{
  return NS_OK;
}

NS_IMETHODIMP
nsSaveMsgListener::OnProgress(PRUint32 aProgress, PRUint32 aProgressMax)
{
  return NS_OK;
}

NS_IMETHODIMP
nsSaveMsgListener::SetMessageKey(PRUint32 aKey)
{
  return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMETHODIMP
nsSaveMsgListener::GetMessageId(nsCString* aMessageId)
{
  return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMETHODIMP
nsSaveMsgListener::OnStopCopy(nsresult aStatus)
{
  if (m_fileSpec)
  {
    nsFileSpec realSpec;
    m_fileSpec->GetFileSpec(&realSpec);
    realSpec.Delete(PR_FALSE);
  }
  Release(); // all done kill ourself
  return aStatus;
}

NS_IMETHODIMP
nsSaveMsgListener::OnStartRequest(nsIRequest* request, nsISupports* aSupport)
{
    nsresult rv = NS_OK;
    if (m_fileSpec)
        rv = m_fileSpec->GetOutputStream(getter_AddRefs(m_outputStream));
    if (NS_FAILED(rv) && m_messenger)
    {
        m_messenger->Alert("saveAttachmentFailed");
    }
    else if (!m_dataBuffer)
    {
        m_dataBuffer = (char*) PR_CALLOC(FOUR_K+1);
    }
    return rv;
}

NS_IMETHODIMP
nsSaveMsgListener::OnStopRequest(nsIRequest* request, nsISupports* aSupport,
                                nsresult status, const PRUnichar* aMsg)
{
  nsresult    rv = NS_OK;

  // rhp: If we are doing the charset conversion magic, this is different
  // processing, otherwise, its just business as usual.
  //
  if ( (m_doCharsetConversion) && (m_fileSpec) )
  {
    char        *conBuf = nsnull;
    PRUint32    conLength = 0; 

    // If we need text/plain, then we need to convert the HTML and then convert
    // to the systems charset
    //
    if (m_outputFormat.EqualsWithConversion(TEXT_PLAIN))
    {
      ConvertBufToPlainText(m_msgBuffer);
      rv = nsMsgI18NSaveAsCharset(TEXT_PLAIN, (const char *)nsAutoCString(nsMsgI18NFileSystemCharset()), 
                                  m_msgBuffer.GetUnicode(), &conBuf); 
      if ( NS_SUCCEEDED(rv) && (conBuf) )
        conLength = nsCRT::strlen(conBuf);
    }

    if ( (NS_SUCCEEDED(rv)) && (conBuf) )
    {
      PRUint32      writeCount;
      rv = m_outputStream->Write(conBuf, conLength, &writeCount);
      if (conLength != writeCount)
        rv = NS_ERROR_FAILURE;
    }

    PR_FREEIF(conBuf);
  }

  // close down the file stream and release ourself
  if (m_fileSpec)
  {
    m_fileSpec->Flush();
    m_fileSpec->CloseStream();
    m_outputStream = null_nsCOMPtr();
  }
  
  if (m_saveAllAttachmentsState)
  {
      m_saveAllAttachmentsState->m_curIndex++;
      if (m_saveAllAttachmentsState->m_curIndex <
          m_saveAllAttachmentsState->m_count)
      {
          char * unescapedUrl = nsnull, * unescapedName = nsnull, 
               * tempCStr = nsnull;
          nsAutoString tempStr;
          nsSaveAllAttachmentsState *state = m_saveAllAttachmentsState;
          PRUint32 i = state->m_curIndex;
          nsCOMPtr<nsIFileSpec> fileSpec;
          nsFileSpec aFileSpec ((const char *) state->m_directoryName);

          rv = NS_NewFileSpec(getter_AddRefs(fileSpec));
          if (NS_FAILED(rv)) goto done;
          unescapedUrl = PL_strdup(state->m_urlArray[i]);
          nsUnescape(unescapedUrl);
          unescapedName = PL_strdup(state->m_displayNameArray[i]);
          nsUnescape(unescapedName);
          rv = ConvertToUnicode(NS_ConvertASCIItoUCS2("UTF-8"), unescapedName, tempStr);
          if (NS_FAILED(rv)) goto done;
          rv = ConvertFromUnicode(nsMsgI18NFileSystemCharset(), tempStr,
                                  &tempCStr);
          if (NS_FAILED(rv)) goto done;
          PR_FREEIF(unescapedName);
          unescapedName = tempCStr;
          aFileSpec += unescapedName;
          rv = m_messenger->PromptIfFileExists(aFileSpec);
          if (NS_FAILED(rv)) goto done;
          fileSpec->SetFromFileSpec(aFileSpec);
          rv = m_messenger->SaveAttachment(fileSpec, unescapedUrl,
                                           state->m_messageUriArray[i],
                                           (void *)state);
      done:
          if (NS_FAILED(rv))
          {
              delete state;
              m_saveAllAttachmentsState = nsnull;
          }
          PR_FREEIF(unescapedUrl);
          PR_FREEIF(unescapedName);
      }
      else
      {
          delete m_saveAllAttachmentsState;
          m_saveAllAttachmentsState = nsnull;
      }
  }
  Release(); // all done kill ourself
  return NS_OK;
}

NS_IMETHODIMP
nsSaveMsgListener::OnDataAvailable(nsIRequest* request, 
                                  nsISupports* aSupport,
                                  nsIInputStream* inStream, 
                                  PRUint32 srcOffset,
                                  PRUint32 count)
{
  nsresult rv = NS_ERROR_FAILURE;
  if (m_dataBuffer && m_outputStream)
  {
    PRUint32 available, readCount, maxReadCount = FOUR_K;
    PRUint32 writeCount;
    rv = inStream->Available(&available);
    while (NS_SUCCEEDED(rv) && available)
    {
      if (maxReadCount > available)
        maxReadCount = available;
      nsCRT::memset(m_dataBuffer, 0, FOUR_K+1);
      rv = inStream->Read(m_dataBuffer, maxReadCount, &readCount);

      // rhp:
      // Ok, now we do one of two things. If we are sending out HTML, then
      // just write it to the HTML stream as it comes along...but if this is
      // a save as TEXT operation, we need to buffer this up for conversion 
      // when we are done. When the stream converter for HTML-TEXT gets in place,
      // this magic can go away.
      //
      if (NS_SUCCEEDED(rv))
      {
        if ( (m_doCharsetConversion) && (m_outputFormat.EqualsWithConversion(TEXT_PLAIN)) )
        {
          PRUnichar       *u = nsnull; 
          nsAutoString    fmt; fmt.AssignWithConversion("%s");
          
          u = nsTextFormatter::smprintf(fmt.GetUnicode(), m_dataBuffer); // this converts UTF-8 to UCS-2 
          if (u)
          {
            PRInt32   newLen = nsCRT::strlen(u);
            m_msgBuffer.Append(u, newLen);
            PR_FREEIF(u);
          }
          else
            m_msgBuffer.AppendWithConversion(m_dataBuffer, readCount);
        }
        else
          rv = m_outputStream->Write(m_dataBuffer, readCount, &writeCount);

        available -= readCount;
      }
    }
  }
  return rv;
}

#define MESSENGER_STRING_URL       "chrome://messenger/locale/messenger.properties"

nsresult
nsMessenger::InitStringBundle()
{
    nsresult res = NS_OK;
    if (!mStringBundle)
    {
		char    *propertyURL = MESSENGER_STRING_URL;

		NS_WITH_SERVICE(nsIStringBundleService, sBundleService,
                        kStringBundleServiceCID, &res);
		if (NS_SUCCEEDED(res) && (nsnull != sBundleService)) 
		{
			nsILocale   *locale = nsnull;
			res = sBundleService->CreateBundle(propertyURL, locale,
                                               getter_AddRefs(mStringBundle));
		}
    }
    return res;
}

PRUnichar *
nsMessenger::GetString(const PRUnichar *aStringName)
{
	nsresult    res = NS_OK;
  PRUnichar   *ptrv = nsnull;

	if (!mStringBundle)
        res = InitStringBundle();

	if (mStringBundle)
		res = mStringBundle->GetStringFromName(aStringName, &ptrv);

  if ( NS_SUCCEEDED(res) && (ptrv) )
    return ptrv;
  else
    return nsCRT::strdup(aStringName);
}

nsSaveAllAttachmentsState::nsSaveAllAttachmentsState(PRUint32 count,
                                                     const char **urlArray,
                                                     const char **nameArray,
                                                     const char **uriArray,
                                                     const char *dirName)
{
    PRUint32 i;
    NS_ASSERTION(count && urlArray && nameArray && uriArray && dirName, 
                 "fatal - invalid parameters\n");
    
    m_count = count;
    m_curIndex = 0;
    m_urlArray = new char*[count];
    m_displayNameArray = new char*[count];
    m_messageUriArray = new char*[count];
    for (i = 0; i < count; i++)
    {
        m_urlArray[i] = nsCRT::strdup(urlArray[i]);
        m_displayNameArray[i] = nsCRT::strdup(nameArray[i]);
        m_messageUriArray[i] = nsCRT::strdup(uriArray[i]);
    }
    m_directoryName = nsCRT::strdup(dirName);
}

nsSaveAllAttachmentsState::~nsSaveAllAttachmentsState()
{
    PRUint32 i;
    for (i = 0; i < m_count; i++)
    {
        nsCRT::free(m_urlArray[i]);
        nsCRT::free(m_displayNameArray[i]);
        nsCRT::free(m_messageUriArray[i]);
    }
    delete m_urlArray;
    delete m_displayNameArray;
    delete m_messageUriArray;
    nsCRT::free(m_directoryName);
}

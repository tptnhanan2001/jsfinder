# -*- coding: utf-8 -*-
#
#  JSFinder - Find links within JS files.
#  Copyright (c) 2025 Nhantieu
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
from javax import swing
from java.awt import Font, Color
from threading import Thread
from array import array
from java.awt import EventQueue
from java.lang import Runnable
from thread import start_new_thread
from javax.swing import JFileChooser

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# Needed params
sensitive_keywords = [
    "admin", "auth", "login", "register", "token", "secret", "session", "config", 
    "password", "jwt", "apikey", "key", "debug", "user", "account", "private"
]

sensitive_response_patterns = [
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",       # Email
    r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",                      # Bearer Token
    r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",    # JWT
    r"(?i)password\s*[:=]\s*['\"]?.{4,30}['\"]?",            # Password field
    r"(?i)access[_-]?token\s*[:=]\s*['\"]?.+?['\"]?",        # Access token
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b",      # Credit card
]


JSExclusionList = ['jquery', 'google-analytics','gpt.js']

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def send_request_to_extracted_links(self, base_url, extracted_links):
        from java.net import URL as JavaURL
        import re

        sensitive_keywords = [
            "admin", "auth", "login", "register", "token", "secret", "session", "config",
            "password", "jwt", "apikey", "key", "debug", "user", "account", "private"
        ]

        sensitive_response_patterns = [
            r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",        # Email
            r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",                        # Bearer Token
            r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",     # JWT
            r"(?i)password\s*[:=]\s*['\"]?.{4,30}['\"]?",             # Password field
            r"(?i)access[_-]?token\s*[:=]\s*['\"]?.+?['\"]?",         # Access token
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b",       # Credit card
        ]

        # 🔍 Thu thập domain in-scope từ site map
        scope_domains = set()
        try:
            for item in self.callbacks.getSiteMap(None):
                try:
                    url = self.helpers.analyzeRequest(item).getUrl()
                    if self.callbacks.isInScope(url):
                        parsed_url = JavaURL(str(url))
                        protocol = parsed_url.getProtocol()
                        host = parsed_url.getHost()
                        port = parsed_url.getPort()
                        scope_domains.add((protocol, host, port))
                except:
                    continue
        except Exception as e:
            self.outputTxtArea.append(u"\n[!] Failed to collect scope domains: {}".format(unicode(str(e), 'utf-8', 'ignore')))
            return

        # 🔁 Với mỗi endpoint được trích xuất
        for item in extracted_links:
            path = item["link"]

            for (protocol, host, port) in scope_domains:
                port = port if port != -1 else (443 if protocol == "https" else 80)

                try:
                    # Build full URL
                    if path.startswith("http://") or path.startswith("https://"):
                        full_url = path
                    elif path.startswith("//"):
                        full_url = protocol + ":" + path
                    elif path.startswith("/"):
                        full_url = protocol + "://" + host + path
                    else:
                        full_url = protocol + "://" + host + "/" + path

                    self.outputTxtArea.append(u"\n\t[>] Trying on domain: {} → {}".format(host, path))

                    request = self.helpers.buildHttpRequest(JavaURL(full_url))
                    service = self.helpers.buildHttpService(host, port, protocol)
                    response = self.callbacks.makeHttpRequest(service, request)

                    analyzed_response = self.helpers.analyzeResponse(response.getResponse())
                    status_code = analyzed_response.getStatusCode()
                    self.outputTxtArea.append(u" [Status: {}]".format(status_code))

                    # 🔒 Nếu path nhạy cảm
                    if any(key in path.lower() for key in sensitive_keywords):
                        self.outputTxtArea.append(u"\n\t[!!] Sensitive-looking endpoint: {}".format(path))

                    # 📦 Decode response safely
                    try:
                        response_bytes = response.getResponse()
                        response_str_raw = self.helpers.bytesToString(response_bytes)
                        if isinstance(response_str_raw, unicode):
                            response_str = response_str_raw
                        else:
                            response_str = response_str_raw.decode('utf-8', 'ignore')
                    except Exception as e:
                        self.outputTxtArea.append(u"\n\t[-] Error decoding response: {}".format(unicode(str(e), 'utf-8', 'ignore')))
                        continue

                    # 🔍 Phân tích nội dung nhạy cảm
                    for pattern in sensitive_response_patterns:
                        match = re.search(pattern, response_str)
                        if match:
                            self.outputTxtArea.append(u"\n\t[⚠️] Sensitive data in response to: {}".format(full_url))
                            self.outputTxtArea.append(u"\n\t     --> {}".format(match.group(0)))
                            break

                except Exception as e:
                    self.outputTxtArea.append(u"\n\t[-] Error with: {} on {} - {}".format(path, host, unicode(str(e), 'utf-8', 'ignore')))


    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JSFinder")

        callbacks.issueAlert("JSFinder Passive Scanner enabled")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)
        self.initUI()
        self.callbacks.addSuiteTab(self)

        print ("JSFinder loaded.")
        print ("Copyright (c) 2025 Nhan.tieu")
        self.outputTxtArea.setText("JSFinder loaded." + "\n" + "Copyright (c) 2025 Nhan.tieu" + "\n")

    def initUI(self):
        self.tab = swing.JPanel()

        # UI for Output
        self.outputLabel = swing.JLabel("LinkFinder Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255,102,52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export Log", actionPerformed=self.exportLog)
        self.parentFrm = swing.JFileChooser()



        # Layout
        layout = swing.GroupLayout(self.tab)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.tab.setLayout(layout)
      
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )
        
        layout.setVerticalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )

    def getTabCaption(self):
        return "JSFinder"

    def getUiComponent(self):
        return self.tab

    def clearLog(self, event):
          self.outputTxtArea.setText("JSFinder loaded." + "\n" + "Developed by nhan.tieu" + "\n" )

    def exportLog(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        print("\n" + "Export to : " + filename)
        open(filename, 'w', 0).write(self.outputTxtArea.text)

    
    def doPassiveScan(self, ihrr):
        try:
            urlReq = ihrr.getUrl()
            testString = str(urlReq)

            linkA = linkAnalyse(ihrr, self.helpers)

            # check if JS file
            if ".js" in testString:
                # Exclude casual JS files
                if any(x in testString for x in JSExclusionList):
                    print("\n" + "[-] URL excluded " + str(urlReq))
                    return None

                # Nếu JS trong scope
                if self.callbacks.isInScope(urlReq):
                    self.outputTxtArea.append("\n" + "[+] Valid in-scope JS found: " + str(urlReq))
                    issueText = linkA.analyseURL()

                    for counter, issue in enumerate(issueText):
                        self.outputTxtArea.append("\n" + "\t" + str(counter) + ' - ' + issue['link'])

                    self.send_request_to_extracted_links(str(urlReq), issueText)

                    issues = ArrayList()
                    issues.add(SRI(ihrr, self.helpers))
                    return issues

                else:
                    # JS nằm ngoài scope nhưng vẫn muốn phân tích
                    print("[-] Out of scope JS URL: " + str(urlReq))
                    issueText = linkA.analyseURL()

                    filtered_links = []
                    for issue in issueText:
                        path = issue['link']
                        try:
                            # Nếu là path (tương đối) thì giữ
                            if path.startswith("/"):
                                filtered_links.append({'link': path})
                            # Nếu là full URL, check scope
                            elif path.startswith("http"):
                                url_obj = URL(path)
                                if self.callbacks.isInScope(url_obj):
                                    filtered_links.append({'link': url_obj.getPath()})
                            # Nếu là file tương đối như "admin.php"
                            elif re.match(r"^[a-zA-Z0-9_\-/.]+\.(php|asp|aspx|jsp|json|action|html|js|txt|xml)", path):
                                filtered_links.append({'link': "/" + path})
                        except Exception as e:
                            continue

                    if filtered_links:
                        self.outputTxtArea.append("\n" + "[+] Out-of-scope JS contains in-scope endpoints from: " + str(urlReq))
                        for i, issue in enumerate(filtered_links):
                            self.outputTxtArea.append("\n\t[InScope] {} - {}".format(i, issue['link']))
                        self.send_request_to_extracted_links(str(urlReq), filtered_links)
                        # Không raise issue vì file JS out-of-scope
                        return None
                    else:
                        print("[-] No in-scope endpoint found in out-of-scope JS.")
                        return None

        except UnicodeEncodeError:
            print("Error in URL decode.")
        return None


    def consolidateDuplicateIssues(self, isb, isa):
        return -1

    def extensionUnloaded(self):
        print "JSFinder unloaded"
        return

class linkAnalyse():
    
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres
        

    regex_str = """
    
      (?:"|')                               # Start newline delimiter
    
      (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    
        |
    
        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
        [^"'><,;|()]{1,})                   # Rest of the characters can't be
    
        |
    
        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/]{1,}                 # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
    
        |
    
        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml)             # . + extension
        (?:\?[^"|']{0,}|))                  # ? mark with parameters
    
      )
    
      (?:"|')                               # End newline delimiter
    
    """     

    def	parser_file(self, content, regex_str, mode=1, more_regex=None, no_dup=1):
        #print ("TEST parselfile #2")
        regex = re.compile(regex_str, re.VERBOSE)
        items = [{"link": m.group(1)} for m in re.finditer(regex, content)]
        if no_dup:
            # Remove duplication
            all_links = set()
            no_dup_items = []
            for item in items:
                if item["link"] not in all_links:
                    all_links.add(item["link"])
                    no_dup_items.append(item)
            items = no_dup_items
    
        # Match Regex
        filtered_items = []
        for item in items:
            # Remove other capture groups from regex results
            if more_regex:
                if re.search(more_regex, item["link"]):
                    #print ("TEST parselfile #3")
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
        return filtered_items

    # Potential for use in the future...
    def threadAnalysis(self):
        thread = Thread(target=self.analyseURL(), args=(session,))
        thread.daemon = True
        thread.start()

    def analyseURL(self):
        
        endpoints = ""
        #print("TEST AnalyseURL #1")
        mime_type=self.helpers.analyzeResponse(self.reqres.getResponse()).getStatedMimeType()
        if mime_type.lower() == 'script':
                url = self.reqres.getUrl()
                encoded_resp=binascii.b2a_base64(self.reqres.getResponse())
                decoded_resp=base64.b64decode(encoded_resp)
                endpoints=self.parser_file(decoded_resp, self.regex_str)
                #print("TEST AnalyseURL #2")
                return endpoints
        return endpoints


class SRI(IScanIssue,ITab):
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Linkfinder Analysed JS files"

    def getIssueType(self):
        return 0x08000000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return "Information"  # "High", "Medium", "Low", "Information" or "False positive"

    def getConfidence(self):
        return "Certain"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("JS files holds links to other parts of web applications. Refer to TAB for results.")

    def getRemediationBackground(self):
        return "This is an <b>informational</b> finding only.<br>"

    def getIssueDetail(self):
        return str("Burp Scanner has analysed the following JS file for links: <b>"
                      "%s</b><br><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        #print ("................raising issue................")
        rra = [self.reqres]
        return rra
        
    def getHttpService(self):
        return self.reqres.getHttpService()
        
        
if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))

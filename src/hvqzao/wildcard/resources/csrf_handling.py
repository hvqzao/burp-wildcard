# CSRF Handling, Copyright (c) 2014 Marcin Woloszyn (@hvqzao), Released under the MIT license

from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter

Yes, No = True, False

class BurpExtender(IBurpExtender, IHttpListener):

    ##############
    #  SETTINGS  #
    ##############

    DEBUG = Yes
    ignore_OutOfScope_RequestResponses = Yes

	# this will be part of extension name --> CSRF Handling (_config_name_)
    SETUP_NAME = '_config_name_' 

    # Search given sequence in *responses* and replace *request params* with response derived values
    CSRF_Tokens = \
    {
    #   param name       CSRF extraction rules
        'token_name': [
                           #dict(start='?token=', stop='\n', chars_remove='\r', status_code=[302, 301]),
                           dict(start='<input type="hidden" name="token" value="', stop='"'),
                         ]
    }

    # Replace string in *requests*
    Request_Literal_Replace = \
    [
        #dict(match='before', replace='after'),
        
    ]
    # Replace string in *responses*
    Response_Literal_Replace = \
    [
        #dict(match='before', replace='after'),
    ]

    ##########
    #  CODE  #
    ##########
    
    # CSRF_Values
    # callbacks
    # helpers
    # stdout
    # stderr
    
    def	registerExtenderCallbacks(self, callbacks):

        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName('CSRF Handling ('+self.SETUP_NAME+')')
        callbacks.registerHttpListener(self)
        self.CSRF_Values = dict()
        for i in self.CSRF_Tokens.keys():
            self.CSRF_Values[i] = None
        if self.DEBUG:
            self.stdout.println('[*] Debug enabled')
        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        if self.ignore_OutOfScope_RequestResponses or self.callbacks.isInScope(self.helpers.analyzeRequest(messageInfo).getUrl()):

            # process request
            
            if messageIsRequest:

                for i in self.Request_Literal_Replace:
                    orig_request = self.helpers.bytesToString(messageInfo.getRequest())
                    if orig_request.find(i['match']) != -1:
                        messageInfo.setRequest(self.helpers.stringToBytes(orig_request.replace(i['match'],i['replace'])))
                        if self.DEBUG:
                            self.stdout.println('[*] Request Literal Replace: "'+i['match']+'" -> "'+i['replace']+'"')

                for i in filter(lambda x: self.CSRF_Values[x] != None, self.CSRF_Values.keys()):
                    orig_parameter = self.helpers.getRequestParameter(messageInfo.getRequest(), i)
                    if orig_parameter != None:
                        new_parameter = self.helpers.buildParameter(i, self.CSRF_Values[i], orig_parameter.getType())
                        messageInfo.setRequest(self.helpers.updateParameter(messageInfo.getRequest(), new_parameter))
                        if self.DEBUG:
                            self.stdout.println('--> Set token: '+i+' = "'+self.CSRF_Values[i]+'"')

            # process response
            
            else:       

                for i in self.Response_Literal_Replace:
                    orig_response = self.helpers.bytesToString(messageInfo.getResponse())
                    if orig_response.find(i['match']) != -1:
                        messageInfo.setResponse(self.helpers.stringToBytes(orig_response.replace(i['match'],i['replace'])))
                        if self.DEBUG:
                            self.stdout.println('[*] Response Literal Replace: "'+i['match']+'" -> "'+i['replace']+'"')

                if self.CSRF_Tokens.keys():
                    for i in self.CSRF_Tokens.keys():
                        conditions = self.CSRF_Tokens[i]
                        if not isinstance(conditions, list):
                            conditions = [conditions]
                        for search in conditions:
                            if 'status_code' in search:
                                status_codes = search['status_code']
                                if not isinstance(status_codes, list):
                                    status_codes = [status_codes]
                                match = False
                                status_code = str(self.helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode())
                                for j in status_codes:
                                    if str(j) == status_code:
                                        match = True
                                if not match:
                                    continue
                            response = self.helpers.bytesToString(messageInfo.getResponse())
                            if 'chars_remove' in search:
                                for j in search['chars_remove']:
                                    response = response.replace(j,'')
                            start_index = response.find(search['start'])
                            if start_index != -1:
                                start_index += len(search['start'])
                                stop_index = response[start_index:].find(search['stop'])
                                if stop_index != -1:
                                    stop_index += start_index
                                    self.CSRF_Values[i] = response[start_index:stop_index]
                                    if self.DEBUG:
                                        self.stdout.println('<-- Got token: '+i+' = "'+response[start_index:stop_index]+'"')

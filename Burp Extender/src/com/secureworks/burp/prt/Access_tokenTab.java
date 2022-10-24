package com.secureworks.burp.prt;

import java.awt.Component;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IRequestInfo;
import burp.IResponseInfo;


public class Access_tokenTab implements IMessageEditorTab
{
    private IMessageEditor msgEditor;
    private byte[] currentMessage;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public Access_tokenTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks)
    {
    	// Save callbacks and helpers
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // Create an instance of message editor
        msgEditor = this.callbacks.createMessageEditor(controller, false);
    }

    //
    // implement IMessageEditorTab
    //

    @Override
    public String getTabCaption()
    {
        return "access_token";
    }

    @Override
    public Component getUiComponent()
    {
    	return msgEditor.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest)
    {
    	if(content.length < BurpUtils.maxSize)
    	{
	        // Enable this tab for access token requests and responses
			if(isRequest)
			{
				// Requests have access token in header:
				// "Authorization: Bearer" or "Authorization: aad"
				IRequestInfo info = helpers.analyzeRequest(content);
				if(BurpUtils.hasBearer(info.getHeaders()))
					return true;
			}
			else if (!isRequest)
			{
				// Response has access_token in resulting json
				IResponseInfo info = helpers.analyzeResponse(content);
	    		
				if(BurpUtils.isJson(info.getHeaders()))
				{
					try
		    		{
						if(BurpUtils.parseJson(content,info.getBodyOffset()).containsKey("access_token"))
							return true;
		    		}
		    		catch(Exception e) {}
				}
			}
    	}

        return false;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest)
    {
        if (content == null)
        {
        	this.currentMessage = null;
        }
        else
        {
        	List<String> headers = null;
        	if(isRequest)
        	{
        		IRequestInfo info = helpers.analyzeRequest(content);
            	headers = info.getHeaders();
        	}
        	else
        	{
        		IResponseInfo info = helpers.analyzeResponse(content);
            	headers = info.getHeaders();
        	}
        	
        	String jws = null;
        	
        	if(BurpUtils.hasBearer(headers))
			{
        		// Extract access token from Authorization header
        		String bearer = BurpUtils.getHeader(headers, "Authorization");
        		jws = bearer.substring(bearer.indexOf(" "));
			}
        	else
        	{
        		try
        		{
        			// Extract access token from body
	        		int bodyOffset=0;
	        		if(isRequest)
	        		{
	        			bodyOffset = helpers.analyzeRequest(content).getBodyOffset();
	        		}
	        		else
	        		{
	        			bodyOffset = helpers.analyzeResponse(content).getBodyOffset();
	        		}
	        		
	        		// Access token is in "access_token"
					jws = BurpUtils.parseJson(content,bodyOffset).get("access_token");
        		}
        		catch(Exception e){};
        	}
        	
        	if(jws != null)
        	{
        		// Extract & decode payload
				try {
					byte[] data = PRTUtils.getJWSPayload(jws);
					byte[] newdata = BurpUtils.setContentType(data, "application/json; charset=utf-8");
	    			msgEditor.setMessage(newdata, isRequest);
				} catch (Exception e) {}
    			
        	}
        	else
        		this.currentMessage = null;
        }
       
    }

    @Override
    public byte[] getMessage()
    {
    	// Just return the original message
        return currentMessage;
    }

    @Override
    public boolean isModified()
    {
    	return msgEditor.isMessageModified();
    }

    @Override
    public byte[] getSelectedData()
    {
    	return msgEditor.getSelectedData();
    }
}

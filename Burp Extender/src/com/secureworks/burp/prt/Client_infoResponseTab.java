package com.secureworks.burp.prt;

import java.awt.Component;
import java.util.Base64;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IResponseInfo;


public class Client_infoResponseTab implements IMessageEditorTab
{
    private IMessageEditor msgEditor;
    private byte[] currentMessage;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public Client_infoResponseTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks)
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
        return "client_info";
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
	        // Enable this tab for client_info requests and responses
			if (!isRequest)
			{
				// Client info has client_info in resulting json
				IResponseInfo info = helpers.analyzeResponse(content);
	    		
				if(BurpUtils.isJson(info.getHeaders()))
				{
					try
		    		{
						if(BurpUtils.parseJson(content,info.getBodyOffset()).containsKey("client_info"))
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
 
    		IResponseInfo info = helpers.analyzeResponse(content);
 
    		try
    		{
        		// Client information is in "client_info"
				byte[] data = Base64.getUrlDecoder().decode(BurpUtils.parseJson(content,info.getBodyOffset()).get("client_info"));
				byte[] newdata = BurpUtils.setContentType(data, "application/json; charset=utf-8");
    			msgEditor.setMessage(newdata, isRequest);

    		}
    		catch(Exception e){};
        	
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

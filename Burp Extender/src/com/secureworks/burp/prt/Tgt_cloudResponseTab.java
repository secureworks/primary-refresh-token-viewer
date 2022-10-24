package com.secureworks.burp.prt;

import java.awt.Component;
import java.nio.charset.StandardCharsets;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IResponseInfo;


public class Tgt_cloudResponseTab implements IMessageEditorTab
{
    private IMessageEditor msgEditor;
    private byte[] currentMessage;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public Tgt_cloudResponseTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks)
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
        return "tgt_cloud";
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
	        // Enable this tab for tgt_cloud requests
			if (!isRequest)
			{
				// Client info has client_info in resulting json
				IResponseInfo info = helpers.analyzeResponse(content);
	    		
				if(BurpUtils.isJson(info.getHeaders()))
				{
					try
		    		{
						if(BurpUtils.parseJson(content,info.getBodyOffset()).containsKey("tgt_cloud"))
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
        		// Azure AD Ticket Granting Ticket is in "tgt_cloud"
				byte[] data = BurpUtils.parseJson(content,info.getBodyOffset()).get("tgt_cloud").getBytes(StandardCharsets.UTF_8);
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

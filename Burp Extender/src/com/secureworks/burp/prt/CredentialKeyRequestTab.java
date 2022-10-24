package com.secureworks.burp.prt;

import java.awt.Component;
import java.util.Map;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IRequestInfo;


public class CredentialKeyRequestTab implements IMessageEditorTab
{
    private IMessageEditor msgEditor;
    private byte[] currentMessage;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public CredentialKeyRequestTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks)
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
        return "CredentialKey";
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
	        // Enable this tab for CredentialKey requests
			if(isRequest)
			{
				IRequestInfo info = helpers.analyzeRequest(content);
				if(BurpUtils.isJson(info.getHeaders()))
				{
					try
		    		{
						Map<String, String> json = BurpUtils.parseJson(content,info.getBodyOffset());
						if(json.containsKey("KeyPurposes") && json.containsKey("key"))
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
        	try
        	{
	      		IRequestInfo info = helpers.analyzeRequest(content);
	      		String jwe = BurpUtils.parseJson(content,info.getBodyOffset()).get("key");
	      		JWEData data = PRTUtils.decryptJWE(jwe,null,callbacks.loadExtensionSetting("SessionKey"));
				
				this.currentMessage = data.getData();
				msgEditor.setMessage(data.getData(), isRequest);
        	}
        	catch(Exception e) {}
      		
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

package com.secureworks.burp.prt;

import java.awt.Component;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IParameter;


public class PRTRequestTab implements IMessageEditorTab
{
    private IMessageEditor msgEditor;
    private byte[] currentMessage;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public PRTRequestTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks)
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
        return "PRT";
    }

    @Override
    public Component getUiComponent()
    {
    	return msgEditor.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest)
    {
        // enable this tab for PRT & getkeydata requests
    	if(isRequest && content.length < BurpUtils.maxSize)
    	{
    		IParameter grant_type = this.helpers.getRequestParameter(content, "grant_type");
    		if(grant_type != null)
    		{
    			// PRT request has "grant_type" parameter with value "urn:ietf:params:oauth:grant-type:jwt-bearer"
    			String strGrant_type = this.helpers.urlDecode(grant_type.getValue());
    			if(strGrant_type.equals("urn:ietf:params:oauth:grant-type:jwt-bearer") && this.helpers.getRequestParameter(content, "request") != null)
    				return true;
    		}
    		// /common/getKeyData has "signedRequest" parameter
    		else if( this.helpers.getRequestParameter(content, "signedRequest") != null)
    			return true;
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
        	// PRT and getKeyData has JWE in "request" and "signedRequest" parameters, respectively. 
        	IParameter request = this.helpers.getRequestParameter(content, "request");
        	if(request == null)
        		request = this.helpers.getRequestParameter(content, "signedRequest");
        	if(request != null)
        	{
        		try
        		{
        			// Extract & decode payload
        			String jws = request.getValue();
            		
        			byte[] data = PRTUtils.getJWSPayload(jws);
        			byte[] newdata = BurpUtils.setContentType(data, "application/json; charset=utf-8");
        			msgEditor.setMessage(newdata, isRequest);
        		}
        		catch(Exception e) {}
        		
    		}
        }
      
        currentMessage = content;
    }

    @Override
    public byte[] getMessage()
    {
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

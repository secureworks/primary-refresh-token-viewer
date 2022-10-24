package com.secureworks.burp.prt;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Base64;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.filechooser.FileNameExtensionFilter;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IResponseInfo;

public class PRTResponseTab implements IMessageEditorTab
{
    private IMessageEditor msgEditor;
    private byte[] currentMessage;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    private JSplitPane rootPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    private JLabel labelTransportKey = new JLabel("Transport Key: ");
    private JTextField textTransportKey = new JTextField(50);
    private JButton btnTransportKey = new JButton("Select");
    private JFileChooser chooser = new JFileChooser();
    private JLabel labelSessionKey = new JLabel("Used Session Key: ");
    private JTextField textSessionKey = new JTextField(50);
    private JLabel labelDecryptedSessionKey = new JLabel("Decrypted Session Key: ");
    private JTextField textDecryptedSessionKey = new JTextField(50);
    private JButton btnDecryptedSessionKey = new JButton("Use");
    
    private void refresh()
    {
    	setMessage(getMessage(), false);
    }

    public PRTResponseTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks)
    {
    	// Save callbacks and helpers
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // Create an instance of message editor
        msgEditor = this.callbacks.createMessageEditor(controller, false);

        // Create top panel 
        Dimension fieldSize = new Dimension(200, textTransportKey.getPreferredSize().height); 
        textTransportKey.setEditable(false);
        textTransportKey.setMinimumSize(fieldSize);
        textTransportKey.setText(callbacks.loadExtensionSetting("TransportKey"));
        textSessionKey.setMinimumSize(fieldSize);
        textSessionKey.setText(callbacks.loadExtensionSetting("SessionKey"));
        textSessionKey.addActionListener(
        		e -> {
        			callbacks.saveExtensionSetting("SessionKey", textSessionKey.getText());
                    this.refresh();
                });
        textDecryptedSessionKey.setEditable(false);
        textDecryptedSessionKey.setMinimumSize(fieldSize);
        btnDecryptedSessionKey.setEnabled(false);
        btnDecryptedSessionKey.addActionListener(
        		e -> {
                    textSessionKey.setText(textDecryptedSessionKey.getText());
                    callbacks.saveExtensionSetting("SessionKey", textSessionKey.getText());
                    textDecryptedSessionKey.setText(null);
                    btnDecryptedSessionKey.setEnabled(false);
                    this.refresh();
                });
        chooser.setFileFilter(new FileNameExtensionFilter("PEM files","pem"));
        btnTransportKey.addActionListener(
        		e -> {
                    int selection = chooser.showOpenDialog(rootPanel);
                    if (selection == JFileChooser.APPROVE_OPTION) {
                    	String transpPortKeyFile = chooser.getSelectedFile().getAbsolutePath();
                        textTransportKey.setText(transpPortKeyFile);
                        callbacks.saveExtensionSetting("TransportKey", transpPortKeyFile);
                        this.refresh();
                    }
                });
        
        JPanel topPanel = new JPanel(new GridBagLayout());
        
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.NORTHWEST;
        constraints.insets = new Insets(0, 10, 0, 10);
        
        constraints.gridx = 0;
        constraints.gridy = 0;
        topPanel.add(labelTransportKey, constraints);
        constraints.gridx = 1;
        topPanel.add(textTransportKey, constraints);
        constraints.gridx = 2;
        topPanel.add(btnTransportKey, constraints);

        constraints.gridx = 0;
        constraints.gridy = 1;
        topPanel.add(labelSessionKey, constraints);
        constraints.gridx = 1;
        topPanel.add(textSessionKey, constraints);
        
        constraints.gridx = 0;
        constraints.gridy = 2;
        topPanel.add(labelDecryptedSessionKey, constraints);
        constraints.gridx = 1;
        topPanel.add(textDecryptedSessionKey, constraints);
        constraints.gridx = 2;
        topPanel.add(btnDecryptedSessionKey, constraints);
        
        
        // Create the UI
        this.rootPanel.setTopComponent(topPanel);
        this.rootPanel.setBottomComponent(msgEditor.getComponent());
        
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
    	return rootPanel;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest)
    {
    	// Enable for PRT and JWE access token responses
    	if(!isRequest && content.length < BurpUtils.maxSize)
    	{
    		IResponseInfo info = helpers.analyzeResponse(content);
    		// PRT has encrypted session key in "session_key_jwe"
    		if (BurpUtils.isJson(info.getHeaders()))
			{
				if(BurpUtils.parseJson(content, info.getBodyOffset()).containsKey("session_key_jwe"))
					return true;
			}
    		// Access token response encrypted as JWE has "application/jose" content-type
    		else if (BurpUtils.isJose(info.getHeaders()))
				return true;
    	}
        return false;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest)
    {
    	textDecryptedSessionKey.setText(null);
    	btnDecryptedSessionKey.setEnabled(false);
    	
        if (content == null)
        {
        	this.currentMessage = null;
        }
        else
        {
        	// Get headers and body
        	IResponseInfo info = helpers.analyzeResponse(content);
    		List<String> headers = info.getHeaders();
    		
    		byte[] body = BurpUtils.getBody(content, info.getBodyOffset());
    		String strBody = new String(body).replace("\0", "");
            
    		if(BurpUtils.isJose(headers))
    		{
    			// Seems to be jwe so try to parse & decrypt it
    			try {
        			// Session key needed
        			if(callbacks.loadExtensionSetting("SessionKey") != null)
        			{
	    				JWEData data = PRTUtils.decryptJWE(strBody,null,callbacks.loadExtensionSetting("SessionKey"));
	    				
	    				byte[] newdata = BurpUtils.setContentType(data.getData(), "application/json; charset=utf-8");
	    					    				
	    				this.currentMessage = newdata;
	    				msgEditor.setMessage(newdata, isRequest);
        			}
    				
				} catch (Exception e) {}
    		}
    		else if(BurpUtils.isJson(headers))
    		{
    			// Seems to have session_key_jwe so try to parse & decrypt
    			try {
   				
    				// Transport key needed
					if(callbacks.loadExtensionSetting("TransportKey") != null)
					{
						String jwe = BurpUtils.parseJson(strBody).get("session_key_jwe");
						
						JWEData data = PRTUtils.decryptJWE(jwe,callbacks.loadExtensionSetting("TransportKey"),null);
						
						String CEK = new String(Base64.getEncoder().encode(data.getCek()));
						
						textDecryptedSessionKey.setText( CEK);
						btnDecryptedSessionKey.setEnabled(true);
						
						this.currentMessage = data.getCek();
						msgEditor.setMessage(data.getCek(), isRequest);
					}
							
				} catch (Exception e) {
					this.currentMessage = null; 
				}
    		}
        }
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

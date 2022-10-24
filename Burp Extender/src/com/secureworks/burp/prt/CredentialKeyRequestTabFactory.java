package com.secureworks.burp.prt;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class CredentialKeyRequestTabFactory implements IMessageEditorTabFactory {

	private IBurpExtenderCallbacks callbacks;

	public CredentialKeyRequestTabFactory(IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
	}
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new CredentialKeyRequestTab(controller, this.callbacks);
	}

}

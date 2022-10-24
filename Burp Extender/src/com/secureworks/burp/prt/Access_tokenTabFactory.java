package com.secureworks.burp.prt;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class Access_tokenTabFactory implements IMessageEditorTabFactory {

	private IBurpExtenderCallbacks callbacks;

	public Access_tokenTabFactory(IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
	}
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new Access_tokenTab(controller, this.callbacks);
	}

}

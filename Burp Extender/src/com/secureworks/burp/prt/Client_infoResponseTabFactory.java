package com.secureworks.burp.prt;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class Client_infoResponseTabFactory implements IMessageEditorTabFactory {

	private IBurpExtenderCallbacks callbacks;

	public Client_infoResponseTabFactory(IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
	}
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new Client_infoResponseTab(controller, this.callbacks);
	}

}

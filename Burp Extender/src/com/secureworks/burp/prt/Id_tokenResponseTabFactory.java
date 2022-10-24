package com.secureworks.burp.prt;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class Id_tokenResponseTabFactory implements IMessageEditorTabFactory {

	private IBurpExtenderCallbacks callbacks;

	public Id_tokenResponseTabFactory(IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
	}
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new Id_tokenResponseTab(controller, this.callbacks);
	}

}

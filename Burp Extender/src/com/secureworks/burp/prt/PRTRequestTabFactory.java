package com.secureworks.burp.prt;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class PRTRequestTabFactory implements IMessageEditorTabFactory {

	private IBurpExtenderCallbacks callbacks;

	public PRTRequestTabFactory(IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
	}
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new PRTRequestTab(controller, this.callbacks);
	}

}

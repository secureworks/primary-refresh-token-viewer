package com.secureworks.burp.prt;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class Tgt_cloudResponseTabFactory implements IMessageEditorTabFactory {

	private IBurpExtenderCallbacks callbacks;

	public Tgt_cloudResponseTabFactory(IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
	}
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new Tgt_cloudResponseTab(controller, this.callbacks);
	}

}

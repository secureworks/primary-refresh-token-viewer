package burp;

import com.secureworks.burp.prt.*;

public class BurpExtender implements IBurpExtender
{
    private IBurpExtenderCallbacks callbacks;
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // Obtain an extension helpers object
    	this.callbacks = callbacks;
                
        // Set our extension name
        callbacks.setExtensionName("Secureworks� Primary Refresh Token (PRT) viewer");
        
        // Register message editor tab factories
        this.callbacks.registerMessageEditorTabFactory(new PRTResponseTabFactory(this.callbacks));
        this.callbacks.registerMessageEditorTabFactory(new PRTRequestTabFactory(this.callbacks));
        this.callbacks.registerMessageEditorTabFactory(new Access_tokenTabFactory(this.callbacks));
        this.callbacks.registerMessageEditorTabFactory(new CredentialKeyRequestTabFactory(this.callbacks));
        this.callbacks.registerMessageEditorTabFactory(new Id_tokenResponseTabFactory(this.callbacks));
        this.callbacks.registerMessageEditorTabFactory(new Client_infoResponseTabFactory(this.callbacks));
        this.callbacks.registerMessageEditorTabFactory(new Tgt_cloudResponseTabFactory(this.callbacks));
        this.callbacks.registerMessageEditorTabFactory(new clientKeyResponseTabFactory(this.callbacks));
        
    }
}

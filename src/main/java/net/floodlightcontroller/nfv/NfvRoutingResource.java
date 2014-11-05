package net.floodlightcontroller.nfv;


import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.Put;
import org.restlet.resource.ServerResource;

public class NfvRoutingResource extends ServerResource {
	@Get("json")
    public String getUrlRouting() {
		NfvRoutingService pihr = (NfvRoutingService)getContext().getAttributes().get(NfvRoutingService.class.getCanonicalName());
		return pihr.getUrlRouting();
    }

	@Put
	@Post
    public void setUrlRouting(String urlRouting, String portRouting) {
		NfvRoutingService pihr = (NfvRoutingService)getContext().getAttributes().get(NfvRoutingService.class.getCanonicalName());
		// We try to get the ID from the URI only if it's not
        // in the POST data 
        String url = (String) getRequestAttributes().get("urlRouting");
        String port = (String) getRequestAttributes().get("portRouting");
	        if (!url.equals("null") && !port.equals("null") )
	        	pihr.setUrlRouting(url, port);
	        else pihr.setUrlRouting(urlRouting, portRouting);
    }
}


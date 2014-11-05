package net.floodlightcontroller.nfv;

import net.floodlightcontroller.restserver.RestletRoutable;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

public class NfvRoutingWebRoutable implements RestletRoutable {
    @Override
    public Restlet getRestlet(Context context) {
        Router router = new Router(context);
        router.attach("/getUrlRouting", NfvRoutingResource.class);//GET
        router.attach("/setUrlRouting/{urlRouting}/port/{portRouting}", NfvRoutingResource.class);//POST
        return router;
    }

    @Override
    public String basePath() {
        return "/nfv/routing";
    }
}


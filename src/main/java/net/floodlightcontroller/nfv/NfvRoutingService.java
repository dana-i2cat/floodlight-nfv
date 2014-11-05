package net.floodlightcontroller.nfv;

import net.floodlightcontroller.core.module.IFloodlightService;

/**
 *
 * @author Josep Batalle (josep.batalle@i2cat.net)
 *
 */
public interface NfvRoutingService extends IFloodlightService {
	public String getBuffer();

	public String getUrlRouting();
	public void setUrlRouting(String urlRouting, String port);
}


package net.floodlightcontroller.nfv;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;
import org.restlet.data.MediaType;
import org.restlet.representation.Representation;
import org.restlet.resource.ClientResource;
import org.restlet.resource.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.BasePacket;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;

public class NfvRouting implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected IStaticFlowEntryPusherService staticFlowEntryPusher;
	protected Set macAddresses;
	protected Set ipAddresses;
	protected static Logger logger;
	protected String urlRouting = null;
	protected String portRouting = null;

	@Override
	public String getName() {
		return NfvRouting.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		BasePacket pkt = (BasePacket) IFloodlightProviderService.bcStore.get(
				cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		// Instantiate two objects for OFMatch and OFPacketIn
		OFPacketIn pin = (OFPacketIn) msg;
logger.info("OF Version: "+msg.getVersion());
logger.info("OF Version: "+msg.getDataAsString(sw, msg, cntx));

		OFMatch match = new OFMatch();
		
		match.loadFromPacket(pin.getPacketData(), pin.getInPort());
		logger.info("Routing ");
	
		logger.info("Layer type "+match.getDataLayerType());
		String type = String.valueOf(match.getDataLayerType());
		if(type.equals("-31011")){//IPv6
			logger.info("IPv6 "+match.getNetworkv6Source());
			logger.info("IPv6 "+match.getNetworkv6Destination());
		}
		if(type.equals("2054")){//IPv6
			
		}
		switch (msg.getType()) {
		case PACKET_IN:
	logger.info("Network Source: "+Integer.toString(match.getNetworkSource()));
	logger.info(Integer.toString(match.getNetworkDestinationMaskLen()));

	
//logger.info(Short.valueOf(match.getDataLayerSource()));
			logger.info("Packet IN detected...");
			if (match.getNetworkSource() != 0 && match.getNetworkDestination() != 0) {

				// String url = "http://"+ urlRouting+ ":"+ portRouting+
				// "/opennaas/ofrouting/VM-Routing1/routing/getRouteTable";
//comment
				String url = "http://" + urlRouting + ":" + portRouting
						+ "/opennaas/ofrouting/VM-Routing1/routing/getPath/"
						+ match.getNetworkSource() + "/"
						+ match.getNetworkDestination() + "/"
						+ sw.getStringId().toString() + "/"
						+ match.getInputPort();
				logger.debug("URL ON : " + url);
				ClientResource service = new ClientResource(url);
				String response = "";
				try {
					Representation string = service.get(MediaType.TEXT_PLAIN);
					response = string.getText();
					logger.info("Routing table " + response);
				} catch (IOException e) {
					e.printStackTrace();
				} catch (ResourceException e) {
					e.printStackTrace();
				}

				logger.info("dest ip: " + IPv4.fromIPv4Address(match.getNetworkSource()));
				logger.info("source ip: " + IPv4.fromIPv4Address(match.getNetworkDestination()));
				logger.info("inputport: " + match.getInputPort());
				logger.info("address: " + sw.getInetAddress());
				logger.info("mac: " + sw.getStringId());
				logger.info("id: " + sw.getId());
				logger.info("The outputPort is: " + response);

				if (!response.equals("null")) {
					logger.info("Response received from OpenNaaS. The outputPort is: " + response);
					List actionsTo = new ArrayList();
					OFAction outputTo = new OFActionOutput(Short.parseShort(response));
					actionsTo.add(outputTo);
					OFMatch newMatch = new OFMatch();
					newMatch.setInputPort(match.getInputPort());
					//
					OFFlowMod fmFrom = new OFFlowMod();
					fmFrom.setType(OFType.FLOW_MOD);
					fmFrom.setPriority((short) 32767);
					// fmFrom.setOutPort(Short.parseShort("3"));
					fmFrom.setMatch(newMatch);
					fmFrom.setActions(actionsTo);
					// fmFrom.setOutPort((short)2);
					fmFrom.setCommand(OFFlowMod.OFPFC_ADD);
					staticFlowEntryPusher.addFlow("FlowTo", fmFrom, sw.getStringId());
				}
			}
			break;
		default:
			break;
		}

		return Command.CONTINUE;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IStaticFlowEntryPusherService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		staticFlowEntryPusher = context.getServiceImpl(IStaticFlowEntryPusherService.class);
		macAddresses = new ConcurrentSkipListSet<Long>();
		ipAddresses = new ConcurrentSkipListSet<Long>();
		logger = LoggerFactory.getLogger(NfvRouting.class);

		Map<String, String> configOptions = context.getConfigParams(this);
		try {
			String idleTimeout = configOptions.get("url");
			String port = configOptions.get("port");
			if (idleTimeout != null) {
				urlRouting = idleTimeout;
			}
			if (port != null) {
				portRouting = port;
			}
		} catch (NumberFormatException e) {
			logger.warn("Error parsing flow idle timeout, "
					+ "using default of {} seconds", urlRouting);
		}
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

}

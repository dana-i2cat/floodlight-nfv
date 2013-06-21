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
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.Wildcards;
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
		logger.info("OF Version: " + msg.getVersion());
		logger.info("OF Version: " + msg.getDataAsString(sw, msg, cntx));

		OFMatch match = new OFMatch();

		match.loadFromPacket(pin.getPacketData(), pin.getInPort());
		logger.info("Routing ");

		logger.info("Layer type " + match.getDataLayerType());
		
		
		if (match.getDataLayerType() == (short) 0x86DD) {// IPv6
			logger.info("IPv6 " + match.getNetworkv6Source());
			logger.info("IPv6 " + match.getNetworkv6Destination());
		}

		switch (msg.getType()) {
case PACKET_IN:
			logger.info("Packet IN detected...");
			logger.info("Network Source: "+ Integer.toString(match.getNetworkSource()));
			long initialTime = System.currentTimeMillis();

			// logger.info(Short.valueOf(match.getDataLayerSource()));
			if (match.getNetworkSource() != 0 && match.getNetworkDestination() != 0) {

				// String url = "http://"+ urlRouting+ ":"+ portRouting+
				// "/opennaas/ofrouting/VM-Routing1/routing/getRouteTable";
				// comment
				String url = "http://" + urlRouting + ":" + portRouting
						+ "/opennaas/ofrouting/VM-Routing1/routing/getSubPath/"
						+ match.getNetworkSource() + "/"
						+ match.getNetworkDestination() + "/"
						+ sw.getStringId().toString() + "/"
						+ match.getInputPort();
				logger.debug("OpenNaaS URL : " + url);
				ClientResource service = new ClientResource(url);
				String response = "";
				String receivedOutPort = "";
				String srcSubnetwork = "";
				String destSubnetwork = "";
				try {
					Representation string = service.get(MediaType.TEXT_PLAIN);
					response = string.getText();
					receivedOutPort = response.split(":")[0];
					srcSubnetwork = response.split(":")[1];
					destSubnetwork = response.split(":")[2];
				} catch (IOException e) {
					e.printStackTrace();
				} catch (ResourceException e) {
					e.printStackTrace();
				}

				logger.info("source ip: "
						+ IPv4.fromIPv4Address(match.getNetworkSource()));
				logger.info("dest ip: "
						+ IPv4.fromIPv4Address(match.getNetworkDestination()));
				logger.info("inputport: " + match.getInputPort());
				logger.info("address: " + sw.getInetAddress());
				logger.info("mac: " + sw.getStringId());
				logger.info("id: " + sw.getId());
				logger.info("Subnets: "+srcSubnetwork+" and "+destSubnetwork);
				logger.info("The outputPort is: " + receivedOutPort);

				if (!receivedOutPort.equals("null")) {
long totalTime = System.currentTimeMillis() - initialTime;
logger.info("fin exec: " + totalTime);

			        
totalTime = System.currentTimeMillis() - initialTime;
logger.info("write exec: " + totalTime);					
					
					logger.info("Response received from OpenNaaS. The outputPort is: "
							+ receivedOutPort);
					short type = Ethernet.TYPE_ARP;
					short inPort = match.getInputPort();
inPort = 0;
					short outPort = Short.parseShort(receivedOutPort);
					int source = match.getNetworkSource();
//source = IPv4.toIPv4Address(srcSubnetwork);
					int dest = match.getNetworkDestination();
//dest = IPv4.toIPv4Address(destSubnetwork);
String mode = "StD";
					for (int i = 0; i<4 ; i++){
						if( i == 1){//dst to src
							inPort = Short.parseShort(receivedOutPort);
							outPort = match.getInputPort();
							source = match.getNetworkDestination();
//source = IPv4.toIPv4Address(destSubnetwork);
							dest = match.getNetworkSource();
mode = "DtS";
						}else if( i == 2){//src to dst
							type = Ethernet.TYPE_IPv4;
							inPort = match.getInputPort();
inPort = 0;
							outPort = Short.parseShort(receivedOutPort);
							source = match.getNetworkSource();
//source = IPv4.toIPv4Address(srcSubnetwork);
							dest = match.getNetworkDestination();
//dest = IPv4.toIPv4Address(destSubnetwork);
mode = "StD";
						}else if( i == 3){//dst to src
							inPort = Short.parseShort(receivedOutPort);
							outPort = match.getInputPort();
							source = match.getNetworkDestination();
//source = IPv4.toIPv4Address(destSubnetwork);
							dest = match.getNetworkSource();
mode = "DtS";
						}
						// ToArp
						List<OFAction> actionsToArp = new ArrayList<OFAction>();
						// Declare the flow
						OFFlowMod fmToArp = new OFFlowMod();
						fmToArp.setType(OFType.FLOW_MOD);
						fmToArp.setPriority((short) 32767);
						// Declare the action
						OFAction outputToArp = new OFActionOutput(outPort);
						actionsToArp.add(outputToArp);
						// Declare the match
						OFMatch mToArp = new OFMatch();
						mToArp.setNetworkSource(source);
						mToArp.setNetworkDestination(dest);
						mToArp.setDataLayerType(type);
					if(inPort != 0)
						mToArp.setInputPort(inPort);
						fmToArp.setActions(actionsToArp);
						fmToArp.setMatch(mToArp);
//mToArp.setWildcards(Wildcards.FULL.withNwDstMask(24));
						// Push the flow
					if(mode.equals("StD")){
						if(type == Ethernet.TYPE_ARP)
							staticFlowEntryPusher.addFlow("arp-mod-"+srcSubnetwork+"/24"+dest, fmToArp, sw.getStringId());
						else
							staticFlowEntryPusher.addFlow("ip4-mod-"+srcSubnetwork+"/24"+dest, fmToArp, sw.getStringId());
					}
					else{
						if(type == Ethernet.TYPE_ARP)
                                                        staticFlowEntryPusher.addFlow("arp-mod-"+srcSubnetwork+"/24"+destSubnetwork+"/24", fmToArp, sw.getStringId());
                                                else
                                                        staticFlowEntryPusher.addFlow("ip4-mod-"+srcSubnetwork+"/24"+destSubnetwork+"/24", fmToArp, sw.getStringId());
					}
				}
/*					
					// ToArp
					List<OFAction> actionsToArp = new ArrayList<OFAction>();
					// Declare the flow
					OFFlowMod fmToArp = new OFFlowMod();
					fmToArp.setType(OFType.FLOW_MOD);
					fmToArp.setPriority((short) 32767);
					// Declare the action
					OFAction outputToArp = new OFActionOutput(Short.parseShort(response));
					actionsToArp.add(outputToArp);
					// Declare the match
					OFMatch mToArp = new OFMatch();
					mToArp.setNetworkSource(match.getNetworkSource());
					mToArp.setNetworkDestination(match.getNetworkDestination());
					mToArp.setDataLayerType(Ethernet.TYPE_ARP);
					mToArp.setInputPort(match.getInputPort());
					fmToArp.setActions(actionsToArp);
					fmToArp.setMatch(mToArp);
					// Push the flow
					staticFlowEntryPusher.addFlow("FlowToArp", fmToArp, sw.getStringId());

					// IPv4
					List<OFAction> actionsTo = new ArrayList<OFAction>();
					// Declare the flow
					OFFlowMod fmTo = new OFFlowMod();
					fmTo.setType(OFType.FLOW_MOD);
					fmTo.setPriority((short) 32767);
					// Declare the action
					OFAction outputTo = new OFActionOutput(Short.parseShort(response));
					actionsTo.add(outputTo);
					// Declare the match
					OFMatch mTo = new OFMatch();
					mTo.setNetworkSource(match.getNetworkSource());
					mTo.setNetworkDestination(match.getNetworkDestination());
					mTo.setDataLayerType(Ethernet.TYPE_IPv4);
					mTo.setInputPort(match.getInputPort());
					fmTo.setActions(actionsTo);
					fmTo.setMatch(mTo);
					// Push the flow
					staticFlowEntryPusher.addFlow("FlowTo", fmTo, sw.getStringId());

					// ArpFrom
					List<OFAction> actionsFromArp = new ArrayList<OFAction>();
					// Declare the flow
					OFFlowMod fmFromArp = new OFFlowMod();
					fmFromArp.setType(OFType.FLOW_MOD);
					fmFromArp.setPriority((short) 32767);
					// Declare the action
					OFAction outputFromArp = new OFActionOutput(match.getInputPort());
					actionsFromArp.add(outputFromArp);
					// Declare the match
					OFMatch mFromArp = new OFMatch();
					mFromArp.setNetworkSource(match.getNetworkDestination());
					mFromArp.setNetworkDestination(match.getNetworkSource());
					mFromArp.setDataLayerType(Ethernet.TYPE_ARP);
					mFromArp.setInputPort(Short.parseShort(response));
					fmFromArp.setActions(actionsFromArp);
					fmFromArp.setMatch(mFromArp);
					// Push the flow
					staticFlowEntryPusher.addFlow("FlowFromArp", fmFromArp, sw.getStringId());
					
					// IPv4-From
					List<OFAction> actionsFrom = new ArrayList<OFAction>();
					// Declare the flow
					OFFlowMod fmFrom = new OFFlowMod();
					fmFrom.setType(OFType.FLOW_MOD);
					fmFrom.setPriority((short) 32767);
					// Declare the action
					OFAction outputFrom = new OFActionOutput(match.getInputPort());
					actionsFrom.add(outputFrom);
					// Declare the match
					OFMatch mFrom = new OFMatch();
					mFrom.setNetworkSource(match.getNetworkDestination());
					mFrom.setNetworkDestination(match.getNetworkSource());
					mFrom.setDataLayerType(Ethernet.TYPE_IPv4);
					mFrom.setInputPort(Short.parseShort(response));
					fmFrom.setActions(actionsFrom);
					fmFrom.setMatch(mFrom);
					// Push the flow
					staticFlowEntryPusher.addFlow("FlowFrom", fmFrom, sw.getStringId());
*/
					totalTime = System.currentTimeMillis() - initialTime;
					logger.info("fin exec: " + totalTime);
				}
				OFPacketOut packetOutMessage = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
		        short packetOutLength = (short)OFPacketOut.MINIMUM_LENGTH; // starting length

		        // Set buffer_id, in_port, actions_len
		        packetOutMessage.setBufferId(pin.getBufferId());
		        packetOutMessage.setInPort(pin.getInPort());
		        packetOutMessage.setActionsLength((short)OFActionOutput.MINIMUM_LENGTH);
		        packetOutLength += OFActionOutput.MINIMUM_LENGTH;

		        // set actions
		        List<OFAction> actions = new ArrayList<OFAction>(1);
		        actions.add(new OFActionOutput(Short.valueOf(receivedOutPort), (short) 0));
		        packetOutMessage.setActions(actions);

		        // set data - only if buffer_id == -1
		        if (pin.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
		            byte[] packetData = pin.getPacketData();
		            packetOutMessage.setPacketData(packetData);
		            packetOutLength += (short)packetData.length;
		        }

		        // finally, set the total length
		        packetOutMessage.setLength(packetOutLength);

		        try {
					sw.write(packetOutMessage, null);
					logger.info("write");
				} catch (IOException e) {
					logger.error("Failed to write {} to switch {}: {}", new Object[]{ packetOutMessage, sw, e });
				}
			}
			if (match.getDataLayerType() == (short) 0x86DD) {// IPv6
				logger.info("IPv6 " + match.getNetworkv6Source());
				logger.info("IPv6 " + match.getNetworkv6Destination());

				// logger.info(Short.valueOf(match.getDataLayerSource()));
				if (!match.getNetworkv6Source().isEmpty() && !match.getNetworkv6Destination().isEmpty()) {
					String url = "http://" + urlRouting + ":" + portRouting
							+ "/opennaas/ofrouting/VM-Routing1/routing/getSubPath/"
							+ match.getNetworkSource() + "/"
							+ match.getNetworkDestination() + "/"
							+ sw.getStringId().toString() + "/"
							+ match.getInputPort();
					logger.debug("OpenNaaS URL : " + url);
					ClientResource service = new ClientResource(url);
					String response = "";
					try {
						Representation string = service.get(MediaType.TEXT_PLAIN);
						response = string.getText();
					} catch (IOException e) {
						e.printStackTrace();
					} catch (ResourceException e) {
						e.printStackTrace();
					}

					logger.info("The outputPort is: " + response);
					short type = Ethernet.TYPE_IPv6;
					short inPort = match.getInputPort();
					short outPort = Short.parseShort(response);
					String source = match.getNetworkv6Source();
					String dest = match.getNetworkv6Destination();
					for (int i = 0; i<2 ; i++){								
						if( i == 1){
							inPort = Short.parseShort(response);
							outPort = match.getInputPort();
							source = match.getNetworkv6Destination();
							dest = match.getNetworkv6Source();
						}
						logger.info("IPv6 not empty");
						// ToArp
						List<OFAction> actionsToArp = new ArrayList<OFAction>();
						// Declare the flow
						OFFlowMod fmToArp = new OFFlowMod();
						fmToArp.setType(OFType.FLOW_MOD);
						fmToArp.setPriority((short) 32767);
						// Declare the action
						OFAction outputToArp = new OFActionOutput(outPort);
						actionsToArp.add(outputToArp);
						// Declare the match
						OFMatch mToArp = new OFMatch();
						mToArp.setNetworkv6Source(source);
						mToArp.setNetworkv6Destination(dest);
						mToArp.setDataLayerType(type);
						mToArp.setInputPort(inPort);
						fmToArp.setActions(actionsToArp);
						fmToArp.setMatch(mToArp);
						// Push the flow
						logger.info("Ipv6 entry pushed");
						staticFlowEntryPusher.addFlow("FlowToArp-"+i+"-"+source, fmToArp, sw.getStringId());
					}
						
/*					logger.info("IPv6 not empty");
					// ToArp
					List<OFAction> actionsToArp = new ArrayList<OFAction>();
					// Declare the flow
					OFFlowMod fmToArp = new OFFlowMod();
					fmToArp.setType(OFType.FLOW_MOD);
					fmToArp.setPriority((short) 32767);
					// Declare the action
					OFAction outputToArp = new OFActionOutput((short) 2);
					actionsToArp.add(outputToArp);
					// Declare the match
					OFMatch mToArp = new OFMatch();
					mToArp.setNetworkv6Source(match.getNetworkv6Source());
					mToArp.setNetworkv6Destination(match.getNetworkv6Destination());
					mToArp.setDataLayerType(Ethernet.TYPE_IPv6);
					mToArp.setInputPort(match.getInputPort());
					fmToArp.setActions(actionsToArp);
					fmToArp.setMatch(mToArp);
					// Push the flow
					logger.info("Ipv6 entry pushed");
					staticFlowEntryPusher.addFlow("FlowToArp", fmToArp, sw.getStringId());
					
					logger.info("Flow from");
					// IPv4-From
					List<OFAction> actionsFrom = new ArrayList<OFAction>();
					// Declare the flow
					OFFlowMod fmFrom = new OFFlowMod();
					fmFrom.setType(OFType.FLOW_MOD);
					fmFrom.setPriority((short) 32767);
					// Declare the action
					OFAction outputFrom = new OFActionOutput(match.getInputPort());
					actionsFrom.add(outputFrom);
					// Declare the match
					OFMatch mFrom = new OFMatch();
					mFrom.setNetworkSource(match.getNetworkDestination());
					mFrom.setNetworkDestination(match.getNetworkSource());
					mFrom.setDataLayerType(Ethernet.TYPE_IPv6);
					mFrom.setInputPort((short) 2);
					fmFrom.setActions(actionsFrom);
					fmFrom.setMatch(mFrom);
					// Push the flow
					staticFlowEntryPusher.addFlow("FlowFrom", fmFrom, sw.getStringId());
					*/
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
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		staticFlowEntryPusher = context
				.getServiceImpl(IStaticFlowEntryPusherService.class);
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

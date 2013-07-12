package net.floodlightcontroller.nfv;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
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
import org.openflow.protocol.OFPacketOut;
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
	protected Boolean proactive = false;

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
//logger.info("OF Version: "+msg.getDataAsString(sw, msg, cntx));
//Boolean proactive = false;
		OFMatch match = new OFMatch();
		
		match.loadFromPacket(pin.getPacketData(), pin.getInPort());
	
//		logger.info("Layer type "+match.getDataLayerType());
//		String type = String.valueOf(match.getDataLayerType());
/*		if(match.getDataLayerType() == (short) 0x86DD){//IPv6
			logger.info("IPv6 "+match.getNetworkv6Source());
			logger.info("IPv6 "+match.getNetworkv6Destination());
		}
*/		short receivedOutPort = 0;
		switch (msg.getType()) {
		case PACKET_IN:
			if (match.getDataLayerType() == (short) 0x800 || match.getDataLayerType() == (short) 0x806) {
	logger.info("Network Source: "+Integer.toString(match.getNetworkSource()));
	logger.info(Integer.toString(match.getNetworkDestinationMaskLen()));
	long initialTime = System.currentTimeMillis();
	
//logger.info(Short.valueOf(match.getDataLayerSource()));
logger.info("Packet IN detected..."+match.getDataLayerType());
			if (match.getNetworkSource() != 0 && match.getNetworkDestination() != 0) {

				// String url = "http://"+ urlRouting+ ":"+ portRouting+
				// "/opennaas/ofrouting/VM-Routing1/routing/getRouteTable";
//comment
				String url = "http://" + urlRouting + ":" + portRouting
						+ "/opennaas/ofrouting/VM-Routing1/routing/getSubPath/"
						+ match.getNetworkSource() + "/"
						+ match.getNetworkDestination() + "/"
						+ sw.getStringId().toString() + "/"
						+ match.getInputPort() + "/"
						+ proactive;
logger.info("OpenNaaS URL: " + url);
				ClientResource service = new ClientResource(url);
				String response = "";
				String srcSubnetwork = "";
				String destSubnetwork = "";
				try {
					Representation string = service.get(MediaType.TEXT_PLAIN);
					response = string.getText();
logger.error("Response: "+response);
					receivedOutPort = Short.valueOf(response.split(":")[0]);
					srcSubnetwork = response.split(":")[1];
					destSubnetwork = response.split(":")[2];
					logger.info("Routing table " + response);
				} catch (IOException e) {
					logger.error("IOException "+e.getMessage());
					e.printStackTrace();
				} catch (ResourceException e) {
					logger.error("ResourceException "+e.getMessage());
					receivedOutPort = 0;
				}catch (NullPointerException e) {
					logger.error("NullPointerException "+e.getMessage());
					receivedOutPort = 0;
				}
				if (receivedOutPort != 0) {
					logger.info("source ip: " + IPv4.fromIPv4Address(match.getNetworkSource()));
					logger.info("dest ip: " + IPv4.fromIPv4Address(match.getNetworkDestination()));
					logger.info("inputport: " + match.getInputPort());
					logger.info("mac: " + sw.getStringId());
					logger.info("Subnets: " + srcSubnetwork + " and " + destSubnetwork);
					logger.info("The outputPort is: " + receivedOutPort);

					logger.info("Response received from OpenNaaS. The outputPort is: " + response);
					long totalTime = System.currentTimeMillis() - initialTime;
					logger.info("fin exec: " + totalTime);

					totalTime = System.currentTimeMillis() - initialTime;
					logger.info("write exec: " + totalTime);

					String name= "";
					String dstIp = "";
					short outP = 0;
					String srcIp = "";
					short inP = 0;
					if (receivedOutPort > 1) {//>4
						name= "arpin-mod-" + IPv4.fromIPv4Address(match.getNetworkDestination());
						dstIp = IPv4.fromIPv4Address(match.getNetworkDestination());
						outP = receivedOutPort;
						setJsonToSend(sw.getStringId(), name, "0x806", srcIp, dstIp, inP, outP);

						name= "ip4in-mod-" + IPv4.fromIPv4Address(match.getNetworkDestination());
						setJsonToSend(sw.getStringId(), name, "0x800", srcIp, dstIp, inP, outP);

						name= "arpto-mod-"+ destSubnetwork + "/24" + srcSubnetwork+"/24";
						dstIp = srcSubnetwork+ "/24";
						outP = match.getInputPort();
						setJsonToSend(sw.getStringId(), name, "0x806", srcIp, dstIp, inP, outP);

						name= "ip4to-mod-" + destSubnetwork+ "/24"+ srcSubnetwork+"/24";
						setJsonToSend(sw.getStringId(), name, "0x800", srcIp, dstIp, inP, outP);

					} else {//output way
						name= "arpto-mod-"+ srcSubnetwork+ "/24" + destSubnetwork+"/24";
						dstIp = destSubnetwork+ "/24";
						outP = receivedOutPort;
						setJsonToSend(sw.getStringId(), name, "0x806", srcIp, dstIp, inP, outP);

						name= "ip4to-mod-" + srcSubnetwork+ "/24"+ destSubnetwork+"/24";
						setJsonToSend(sw.getStringId(), name, "0x800", srcIp, dstIp, inP, outP);

						name= "arpin-mod-" + IPv4.fromIPv4Address(match.getNetworkSource());
						dstIp = IPv4.fromIPv4Address(match.getNetworkSource());
						outP = match.getInputPort();
						setJsonToSend(sw.getStringId(), name, "0x806", srcIp, dstIp, inP, outP);

						name= "ip4in-mod-" + IPv4.fromIPv4Address(match.getNetworkSource());
						setJsonToSend(sw.getStringId(), name, "0x800", srcIp, dstIp, inP, outP);

					}

					totalTime = System.currentTimeMillis() - initialTime;
					logger.info("write exec: " + totalTime);

					logger.info("Response received from OpenNaaS. The outputPort is: "
							+ receivedOutPort);
				}
			}
			}
/*			if (match.getDataLayerType() == (short) 0x86DD) {// IPv6
				logger.info("IPv6 " + match.getNetworkv6Source());
				logger.info("IPv6 " + match.getNetworkv6Destination());
				
				try {
					InetAddress srcAddr = InetAddress.getByName(match.getNetworkv6Source());
					InetAddress dstAddr = InetAddress.getByName(match.getNetworkv6Destination());
				} catch (UnknownHostException e1) {
					logger.error("UnknownHostException");
					match.setNetworkv6Source(null);
					match.setNetworkv6Destination(null);
					e1.printStackTrace();
				}
				// logger.info(Short.valueOf(match.getDataLayerSource()));
				if (!match.getNetworkv6Source().isEmpty() && !match.getNetworkv6Destination().isEmpty()) {
					String url = "http://" + urlRouting + ":" + portRouting
							+ "/opennaas/ofrouting/VM-Routing1/routing/getSubPath/"
							+ match.getNetworkv6Source() + "/"
							+ match.getNetworkv6Destination() + "/"
							+ sw.getStringId().toString() + "/"
							+ match.getInputPort() + "/"
							+ proactive;
					logger.error("OpenNaaS URL : " + url);
					ClientResource service = new ClientResource(url);
					String response = "";
					String srcSubnetwork = "";
					String destSubnetwork = "";
					try {
						Representation string = service.get(MediaType.TEXT_PLAIN);
						response = string.getText();
						receivedOutPort = Short.valueOf(response.split(":")[0]);
						srcSubnetwork = response.split(":")[1];
						destSubnetwork = response.split(":")[2];
					} catch (IOException e) {
						logger.error("IOException "+e.getMessage());
						e.printStackTrace();
					} catch (ResourceException e) {
						logger.error("ResourceException"+e.getMessage());
						receivedOutPort = 0;					
					}
					if (receivedOutPort != 0) {
						logger.info("The outputPort is: " + receivedOutPort);
						short type = Ethernet.TYPE_IPv6;
						short inPort = match.getInputPort();
						short outPort = receivedOutPort;
						String source = match.getNetworkv6Source();
						String dest = match.getNetworkv6Destination();
						for (int i = 0; i < 2; i++) {
							if (i == 1) {
								inPort = receivedOutPort;
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
							mToArp.setDataLayerType(type);
							mToArp.setNetworkv6Source(source);
							mToArp.setNetworkv6Destination(dest);
							mToArp.setDataLayerType(type);
							mToArp.setInputPort(inPort);
							fmToArp.setActions(actionsToArp);
							fmToArp.setMatch(mToArp);
							// Push the flow
							logger.error(fmToArp.toString());
							
							logger.info("Ipv6 entry pushed");
							staticFlowEntryPusher.addFlow("FlowToArp-" + i + "-"
									+ source, fmToArp, sw.getStringId());
						}
					}

				}
			}
*/			if (receivedOutPort != 0) {
				OFPacketOut packetOutMessage = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
				short packetOutLength = (short) OFPacketOut.MINIMUM_LENGTH; // starting
																			// length
						// Set buffer_id, in_port, actions_len
				packetOutMessage.setBufferId(pin.getBufferId());
				packetOutMessage.setInPort(pin.getInPort());
				packetOutMessage.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
				packetOutLength += OFActionOutput.MINIMUM_LENGTH;
						// set actions
				List<OFAction> actions = new ArrayList<OFAction>(1);
				actions.add(new OFActionOutput(Short.valueOf(receivedOutPort), (short) 0));
				packetOutMessage.setActions(actions);
						// set data - only if buffer_id == -1
				if (pin.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
					byte[] packetData = pin.getPacketData();
					packetOutMessage.setPacketData(packetData);
					packetOutLength += (short) packetData.length;
				}
						// finally, set the total length
				packetOutMessage.setLength(packetOutLength);
						try {
					sw.write(packetOutMessage, null);
					logger.info("write");
				} catch (IOException e) {
				logger.error("Failed to write {} to switch {}: {}",
								new Object[] { packetOutMessage, sw, e });
				}
			}

			break;
		default:
			break;
		}

		return Command.STOP;
	}
	
	private String setJsonToSend(String mac, String name, String type, String SrcIp, String DstIp, short inP, short outP){
		String json = "{\"switch\": \""+mac+"\", \"name\":\""+name+"\", \"ether-type\":\""+type+"\", \"dst-ip\":\""
				+ DstIp+ "\" ,\"priority\":\"32767\",\"active\":\"true\", \"actions\":\"output="+outP+ "\"}";
		
		if(!SrcIp.equals("")){
			json = "{\"switch\": \""+mac+"\", \"name\":\""+name+"\", \"ether-type\":\""+type+"\",  \"src-ip\":\""
					+ SrcIp+ "\" , \"dst-ip\":\""+ DstIp+ "\" ,\"priority\":\"32767\",\"active\":\"true\", \"actions\":\"output="+outP+ "\"}";
		}
		staticFlowEntryPusher.addFlowFromJSON("arp-mod-", json, mac);
		return json;
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
			String nfvType = configOptions.get("NFVType");
			if (idleTimeout != null) {
				urlRouting = idleTimeout;
			}
			if (port != null) {
				portRouting = port;
			}
			if (proactive != null){
				proactive = Boolean.valueOf(nfvType);
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

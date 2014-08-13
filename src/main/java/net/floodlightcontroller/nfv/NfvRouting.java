package net.floodlightcontroller.nfv;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

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

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.restlet.data.ChallengeScheme;
import org.restlet.data.MediaType;
import org.restlet.representation.Representation;
import org.restlet.resource.ClientResource;
import org.restlet.resource.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author Josep Batallé (josep.batalle@i2cat.net)
 *
 */
public class NfvRouting implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected IStaticFlowEntryPusherService staticFlowEntryPusher;
	protected static Logger logger;
	protected String urlRouting = null;
	protected String portRouting = null;
	protected Boolean proactive = false;
	protected String user = "admin";
	protected String password = "123456";

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

		OFMatch match = new OFMatch();
		match.loadFromPacket(pin.getPacketData(), pin.getInPort());

		short receivedOutPort = 0;
		switch (msg.getType()) {
		case PACKET_IN:
			if (match.getDataLayerType() == (short) 0x800 || match.getDataLayerType() == (short) 0x806) {
				logger.info("Network Source: "+Integer.toString(match.getNetworkSource()));
				logger.info(Integer.toString(match.getNetworkDestinationMaskLen()));
				long initialTime = System.currentTimeMillis();

				//logger.info(Short.valueOf(match.getDataLayerSource()));
				logger.info("Packet IN detected..."+match.getDataLayerType());
				if (match.getNetworkSource() != 0 && match.getNetworkDestination() != 0) {

//					String url = "http://"+user+":"+password+"@" + urlRouting + ":" + portRouting + "/"
					String url = "http://" + urlRouting + ":" + portRouting + "/"
							+ "opennaas/vrf/routing/route/"
							+ match.getNetworkSource() + "/"
							+ match.getNetworkDestination() + "/"
							+ sw.getStringId().toString() + "/"
							+ match.getInputPort();
					logger.info("OpenNaaS URL: " + url);
					ClientResource service = new ClientResource(url);
					service.setChallengeResponse(ChallengeScheme.HTTP_BASIC, user, password);
					String response = "";
					try {
						Representation string = service.get(MediaType.TEXT_PLAIN);
						response = string.getText();
						logger.debug("Response: "+response);
						receivedOutPort = Short.valueOf(response.split(":")[0]);
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
						logger.debug("Source ip: " + IPv4.fromIPv4Address(match.getNetworkSource()));
						logger.debug("Destination ip: " + IPv4.fromIPv4Address(match.getNetworkDestination()));
						logger.debug("inputport: " + match.getInputPort());
						logger.debug("mac: " + sw.getStringId());

						configureFlows(match, sw, receivedOutPort);
					}
				}
			}
/* IPv6 not supported yet
			if (match.getDataLayerType() == (short) 0x86DD) {// IPv6
			}
*/
			//Send packet-out to switch
			if (receivedOutPort != 0) {
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

	private void configureFlows(OFMatch match, IOFSwitch sw, short receivedOutPort){
		String name= "";
		String dstIp = "";
		short outP = 0;
		String srcIp = "";
		short inP = 0;

		//output way
		srcIp = IPv4.fromIPv4Address(match.getNetworkSource());
		dstIp = IPv4.fromIPv4Address(match.getNetworkDestination());
		name = createFlowName("2054", srcIp, dstIp, sw.getStringId().substring(sw.getStringId().length() - 2));
		outP = receivedOutPort;
		setJsonToSend(sw.getStringId(), name, "0x806", srcIp, dstIp, inP, outP);

		name = createFlowName("2048", srcIp, dstIp, sw.getStringId().substring(sw.getStringId().length() - 2));
		setJsonToSend(sw.getStringId(), name, "0x800", srcIp, dstIp, inP, outP);

		srcIp = IPv4.fromIPv4Address(match.getNetworkDestination());
		dstIp = IPv4.fromIPv4Address(match.getNetworkSource());
		name = createFlowName("2054", srcIp, dstIp, sw.getStringId().substring(sw.getStringId().length() - 2));
		outP = match.getInputPort();
		setJsonToSend(sw.getStringId(), name, "0x806", srcIp, dstIp, inP, outP);

		name = createFlowName("2048", srcIp, dstIp, sw.getStringId().substring(sw.getStringId().length() - 2));
		setJsonToSend(sw.getStringId(), name, "0x800", srcIp, dstIp, inP, outP);
	}

	private String createFlowName(String type, String srcIp, String dstIp, String swId){
		String name = "0-"+type+"-" + srcIp + "-" + dstIp + "-"+swId;
		return name;
	}

	private String setJsonToSend(String mac, String name, String type, String SrcIp, String DstIp, short inP, short outP){
		String json = "{\"switch\": \""+mac+"\", \"name\":\""+name+"\", \"ether-type\":\""+type+"\", \"dst-ip\":\""
				+ DstIp+ "\" ,\"priority\":\"32767\",\"active\":\"true\", \"actions\":\"output="+outP+ "\"}";

		if(!SrcIp.equals("")){
			json = "{\"switch\": \""+mac+"\", \"name\":\""+name+"\", \"ether-type\":\""+type+"\",  \"src-ip\":\""
					+ SrcIp+ "\" , \"dst-ip\":\""+ DstIp+ "\" ,\"priority\":\"32767\",\"active\":\"true\", \"actions\":\"output="+outP+ "\"}";
		}
		staticFlowEntryPusher.addFlowFromJSON(name, json, mac);
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
		logger = LoggerFactory.getLogger(NfvRouting.class);

		Map<String, String> configOptions = context.getConfigParams(this);
		try {
			String url = configOptions.get("url");
			String port = configOptions.get("port");
			String nfvType = configOptions.get("NFVType");
			if (url != null) {
				urlRouting = url;
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

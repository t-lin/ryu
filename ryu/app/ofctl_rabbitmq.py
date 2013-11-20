# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import ctypes
import struct
import datetime
import calendar
import gflags
import pika
import threading
import weakref, traceback

import json
from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib import ofctl_v1_0
from ryu.lib.mac import haddr_to_bin, ipaddr_to_bin
from janus.network.of_controller import event_contents

FLAGS = gflags.FLAGS

LOG = logging.getLogger('ryu.app.ofctl_rabbitmq')

    
LOG_FORMAT = ('%(levelname) -10s %(asctime)s %(name) -30s %(funcName) '
              '-35s %(lineno) -5d: %(message)s')
LOGGER = logging.getLogger(__name__)


class RabbitStatsApi(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }
    
    EXCHANGE = 'janusRabbitEvents_exchange'
    EXCHANGE_TYPE = 'fanout'
    QUEUE = 'janusRabbitEvents_queue'
    ROUTING_KEY = ''

    def __init__(self, *args, **kwargs):
        self.dpset = kwargs['dpset']
        
        self.rabbit_user = FLAGS.rabbit_user
        self.rabbit_password = FLAGS.rabbit_password
        self.rabbit_host = FLAGS.rabbit_host
        self._connection = None
        self._channel = None
        self._closing = False
        self._consumer_tag = None
        self._url = 'amqp://%s:%s@%s:5672' % (self.rabbit_user, self.rabbit_password, self.rabbit_host) + '/%2F'
        logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
        self.rd = threading.Thread(name = 'RabbitDispatcher', target = self.run)
        self.rd.setDaemon('True')
        self.rd.start()

    def output_packet(self, body_dict, dpset):
        LOG.info("OFCTL_RABBITMQ processed the packet as output_packet")
        print body_dict
        dpid = body_dict['dpid']
        buffer_id = body_dict['buffer_id']
        in_port = body_dict['in_port']

        try:
            out_port_list = body_dict.get('out_port_list')
            mydata = body_dict.get('data')
            assert type(body_dict) is dict
            #TODO: put assert for mydata, but sometimes data might be Null
            #assert type(mydata) is str
            assert type(out_port_list) is list
        except SyntaxError:
            LOG.debug('invalid syntax %s', body_dict)

        datapath = dpset.get(dpid)
        assert datapath is not None
        ofproto = datapath.ofproto

        actions = []
        for out_port in out_port_list:
            actions.append(datapath.ofproto_parser.OFPActionOutput(int(out_port)))

        if mydata is not None:
            mydata = eval(mydata)
            src = mydata.get(event_contents.DL_SRC)
            dst = mydata.get(event_contents.DL_DST)
            _eth_type = mydata.get(event_contents.ETH_TYPE)
            HTYPE = mydata.get(event_contents.ARP_HTYPE)
            PTYPE = mydata.get(event_contents.ARP_PTYPE)
            HLEN = mydata.get(event_contents.ARP_HLEN)
            PLEN = mydata.get(event_contents.ARP_PLEN)
            OPER = mydata.get(event_contents.ARP_OPER)
            SPA = mydata.get(event_contents.ARP_SPA)
            SHA = mydata.get(event_contents.ARP_SHA)
            TPA = mydata.get(event_contents.ARP_TPA)
            THA = mydata.get(event_contents.ARP_THA)

            mybuffer = ctypes.create_string_buffer(42)

            struct.pack_into('!6s6sHHHbbH6s4s6s4s',
                             mybuffer, 0, haddr_to_bin(src), haddr_to_bin(dst),
                             _eth_type, HTYPE, PTYPE, HLEN, PLEN, OPER,
                             haddr_to_bin(SHA), ipaddr_to_bin(SPA),
                             haddr_to_bin(THA), ipaddr_to_bin(TPA))
            datapath.send_packet_out(actions=actions, data=mybuffer)
        else:
            datapath.send_packet_out(int(buffer_id), int(in_port), actions=actions, data=None)

    def drop_packet(self, body_dict, dpset):
        LOG.info("OFCTL_RABBITMQ processed the packet as drop_packet")
        dpid = body_dict['dpid']
        buffer_id = body_dict['buffer_id']
        in_port = body_dict['in_port']

        datapath = dpset.get(dpid)
        assert datapath is not None
        LOG.info('\nthe packet is going to be dropped. dpid=%s, in_port=%s\n', dpid, in_port)
        datapath.send_packet_out(buffer_id, in_port, [])

    def mod_flow_entry(self, cmd, body_dict, dpset):
        LOG.info("OFCTL_RABBITMQ processed the packet as mod_flow_entry")
        try:
            flow = body_dict
        except SyntaxError:
            LOG.debug('invalid syntax %s', body_dict)

        dpid = flow.get('dpid')
        dp = dpset.get(int(dpid))
        if dp is None:
            return

        if cmd == 'add':
            cmd = dp.ofproto.OFPFC_ADD
        elif cmd == 'modify':
            cmd = dp.ofproto.OFPFC_MODIFY
        elif cmd == 'delete':
            cmd = dp.ofproto.OFPFC_DELETE
        else:
            return

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            ofctl_v1_0.mod_flow_entry(dp, flow, cmd)
        else:
            LOG.debug('Unsupported OF protocol')
            return

    def delete_flow_entry(self, body_dict, dpset):
        dp = dpset.get(int(dpid))
        if dp is None:
            return

        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            ofctl_v1_0.delete_flow_entry(dp)
        else:
            LOG.debug('Unsupported OF protocol')
            return

        return

    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)
        print 'stats_reply_handler:', msgs

        if msg.flags & dp.ofproto.OFPSF_REPLY_MORE:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def desc_stats_reply_handler(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        self.stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        self.stats_reply_handler(ev)
        
    

    def connect(self):
        """This method connects to RabbitMQ, returning the connection handle.
        When the connection is established, the on_connection_open method
        will be invoked by pika.

        :rtype: pika.SelectConnection

        """
        LOGGER.info('Connecting to %s', self._url)
        return pika.SelectConnection(pika.URLParameters(self._url),
                                     self.on_connection_open,
                                     stop_ioloop_on_close=False)

    def close_connection(self):
        """This method closes the connection to RabbitMQ."""
        LOGGER.info('Closing connection')
        self._connection.close()

    def add_on_connection_close_callback(self):
        """This method adds an on close callback that will be invoked by pika
        when RabbitMQ closes the connection to the publisher unexpectedly.

        """
        LOGGER.info('Adding connection close callback')
        self._connection.add_on_close_callback(self.on_connection_closed)

    def on_connection_closed(self, connection, reply_code, reply_text):
        """This method is invoked by pika when the connection to RabbitMQ is
        closed unexpectedly. Since it is unexpected, we will reconnect to
        RabbitMQ if it disconnects.

        :param pika.connection.Connection connection: The closed connection obj
        :param int reply_code: The server provided reply_code if given
        :param str reply_text: The server provided reply_text if given

        """
        self._channel = None
        if self._closing:
            self._connection.ioloop.stop()
        else:
            LOGGER.warning('Connection closed, reopening in 1 seconds: (%s) %s',
                           reply_code, reply_text)
            self._connection.add_timeout(1, self.reconnect)

    def on_connection_open(self, unused_connection):
        """This method is called by pika once the connection to RabbitMQ has
        been established. It passes the handle to the connection object in
        case we need it, but in this case, we'll just mark it unused.

        :type unused_connection: pika.SelectConnection

        """
        LOGGER.info('Connection opened')
        self.add_on_connection_close_callback()
        self.open_channel()

    def reconnect(self):
        """Will be invoked by the IOLoop timer if the connection is
        closed. See the on_connection_closed method.

        """
        # This is the old connection IOLoop instance, stop its ioloop
        self._connection.ioloop.stop()

        if not self._closing:

            # Create a new connection
            self._connection = self.connect()

            # There is now a new connection, needs a new ioloop to run
            self._connection.ioloop.start()

    def add_on_channel_close_callback(self):
        """This method tells pika to call the on_channel_closed method if
        RabbitMQ unexpectedly closes the channel.

        """
        LOGGER.info('Adding channel close callback')
        self._channel.add_on_close_callback(self.on_channel_closed)

    def on_channel_closed(self, channel, reply_code, reply_text):
        """Invoked by pika when RabbitMQ unexpectedly closes the channel.
        Channels are usually closed if you attempt to do something that
        violates the protocol, such as re-declare an exchange or queue with
        different parameters. In this case, we'll close the connection
        to shutdown the object.

        :param pika.channel.Channel: The closed channel
        :param int reply_code: The numeric reason the channel was closed
        :param str reply_text: The text reason the channel was closed

        """
        LOGGER.warning('Channel %i was closed: (%s) %s',
                       channel, reply_code, reply_text)
        self._connection.close()

    def on_channel_open(self, channel):
        """This method is invoked by pika when the channel has been opened.
        The channel object is passed in so we can make use of it.

        Since the channel is now open, we'll declare the exchange to use.

        :param pika.channel.Channel channel: The channel object

        """
        LOGGER.info('Channel opened')
        self._channel = channel
        self.add_on_channel_close_callback()
        self.setup_exchange(self.EXCHANGE)

    def setup_exchange(self, exchange_name):
        """Setup the exchange on RabbitMQ by invoking the Exchange.Declare RPC
        command. When it is complete, the on_exchange_declareok method will
        be invoked by pika.

        :param str|unicode exchange_name: The name of the exchange to declare

        """
        LOGGER.info('Declaring exchange %s', exchange_name)
        self._channel.exchange_declare(self.on_exchange_declareok,
                                       exchange_name,
                                       self.EXCHANGE_TYPE)

    def on_exchange_declareok(self, unused_frame):
        """Invoked by pika when RabbitMQ has finished the Exchange.Declare RPC
        command.

        :param pika.Frame.Method unused_frame: Exchange.DeclareOk response frame

        """
        LOGGER.info('Exchange declared')
        self.setup_queue(self.QUEUE)

    def setup_queue(self, queue_name):
        """Setup the queue on RabbitMQ by invoking the Queue.Declare RPC
        command. When it is complete, the on_queue_declareok method will
        be invoked by pika.

        :param str|unicode queue_name: The name of the queue to declare.

        """
        LOGGER.info('Declaring queue %s', queue_name)
        self._channel.queue_declare(self.on_queue_declareok, queue_name, exclusive=True)

    def on_queue_declareok(self, method_frame):
        """Method invoked by pika when the Queue.Declare RPC call made in
        setup_queue has completed. In this method we will bind the queue
        and exchange together with the routing key by issuing the Queue.Bind
        RPC command. When this command is complete, the on_bindok method will
        be invoked by pika.

        :param pika.frame.Method method_frame: The Queue.DeclareOk frame

        """
        LOGGER.info('Binding %s to %s with %s',
                    self.EXCHANGE, self.QUEUE, self.ROUTING_KEY)
        self._channel.queue_bind(self.on_bindok, self.QUEUE,
                                 self.EXCHANGE, self.ROUTING_KEY)

    def add_on_cancel_callback(self):
        """Add a callback that will be invoked if RabbitMQ cancels the consumer
        for some reason. If RabbitMQ does cancel the consumer,
        on_consumer_cancelled will be invoked by pika.

        """
        LOGGER.info('Adding consumer cancellation callback')
        self._channel.add_on_cancel_callback(self.on_consumer_cancelled)

    def on_consumer_cancelled(self, method_frame):
        """Invoked by pika when RabbitMQ sends a Basic.Cancel for a consumer
        receiving messages.

        :param pika.frame.Method method_frame: The Basic.Cancel frame

        """
        LOGGER.info('Consumer was cancelled remotely, shutting down: %r',
                    method_frame)
        if self._channel:
            self._channel.close()

    def acknowledge_message(self, delivery_tag):
        """Acknowledge the message delivery from RabbitMQ by sending a
        Basic.Ack RPC method for the delivery tag.

        :param int delivery_tag: The delivery tag from the Basic.Deliver frame

        """
        #LOGGER.info('Acknowledging message %s', delivery_tag)
        self._channel.basic_ack(delivery_tag)

    def on_message(self, unused_channel, basic_deliver, properties, body):
        """Invoked by pika when a message is delivered from RabbitMQ. The
        channel is passed for your convenience. The basic_deliver object that
        is passed in carries the exchange, routing key, delivery tag and
        a redelivered flag for the message. The properties passed in is an
        instance of BasicProperties with the message properties and the body
        is the message that was sent.

        :param pika.channel.Channel unused_channel: The channel object
        :param pika.Spec.Basic.Deliver: basic_deliver method
        :param pika.Spec.BasicProperties: properties
        :param str|unicode body: The message body

        """
        #LOGGER.info('Received message # %s from %s: %s',
        #            basic_deliver.delivery_tag, properties.app_id, body)
        
        output_rabbit_api = 'packetActionOutput'
        drop_rabbit_api = 'packetActionDrop'
        addFlow_rabbit_api = 'flowentryAdd'
        delFlow_rabbit_api = 'flowentryDelete'
        
        try:
            body_dict = json.loads(body)
            method_name = body_dict['method_name']
            if method_name == output_rabbit_api:
                self.output_packet(body_dict, self.dpset)
            elif method_name == drop_rabbit_api:
                self.drop_packet(body_dict, self.dpset)
            elif method_name == addFlow_rabbit_api:
                self.mod_flow_entry('add', body_dict, self.dpset)
            elif method_name == delFlow_rabbit_api:
                self.mod_flow_entry('delete', body_dict, self.dpset)
            elif method_name == delAllFlow_rabbit_api:
                    self.delete_flow_entry(body_dict, dpset)
            #ch.basic_ack(delivery_tag = method.delivery_tag)
        except Exception as e:
            LOG.info("EXCEPTION IN CONSUMING RABBIT QUEUES")
            trace = traceback.format_exc()
            print trace
        else:
            trace = None
        finally:
            if trace:
                print trace
            pass
    
        self.acknowledge_message(basic_deliver.delivery_tag)

    def on_cancelok(self, unused_frame):
        """This method is invoked by pika when RabbitMQ acknowledges the
        cancellation of a consumer. At this point we will close the channel.
        This will invoke the on_channel_closed method once the channel has been
        closed, which will in-turn close the connection.

        :param pika.frame.Method unused_frame: The Basic.CancelOk frame

        """
        LOGGER.info('RabbitMQ acknowledged the cancellation of the consumer')
        self.close_channel()

    def stop_consuming(self):
        """Tell RabbitMQ that you would like to stop consuming by sending the
        Basic.Cancel RPC command.

        """
        if self._channel:
            LOGGER.info('Sending a Basic.Cancel RPC command to RabbitMQ')
            self._channel.basic_cancel(self.on_cancelok, self._consumer_tag)

    def start_consuming(self):
        """This method sets up the consumer by first calling
        add_on_cancel_callback so that the object is notified if RabbitMQ
        cancels the consumer. It then issues the Basic.Consume RPC command
        which returns the consumer tag that is used to uniquely identify the
        consumer with RabbitMQ. We keep the value to use it when we want to
        cancel consuming. The on_message method is passed in as a callback pika
        will invoke when a message is fully received.

        """
        LOGGER.info('Issuing consumer related RPC commands')
        self.add_on_cancel_callback()
        self._consumer_tag = self._channel.basic_consume(self.on_message,
                                                         self.QUEUE)

    def on_bindok(self, unused_frame):
        """Invoked by pika when the Queue.Bind method has completed. At this
        point we will start consuming messages by calling start_consuming
        which will invoke the needed RPC commands to start the process.

        :param pika.frame.Method unused_frame: The Queue.BindOk response frame

        """
        LOGGER.info('Queue bound')
        self.start_consuming()

    def close_channel(self):
        """Call to close the channel with RabbitMQ cleanly by issuing the
        Channel.Close RPC command.

        """
        LOGGER.info('Closing the channel')
        self._channel.close()

    def open_channel(self):
        """Open a new channel with RabbitMQ by issuing the Channel.Open RPC
        command. When RabbitMQ responds that the channel is open, the
        on_channel_open callback will be invoked by pika.

        """
        LOGGER.info('Creating a new channel')
        self._connection.channel(on_open_callback=self.on_channel_open)

    def run(self):
        """Run the example consumer by connecting to RabbitMQ and then
        starting the IOLoop to block and allow the SelectConnection to operate.

        """
        self._connection = self.connect()
        self._connection.ioloop.start()

    def stop(self):
        """Cleanly shutdown the connection to RabbitMQ by stopping the consumer
        with RabbitMQ. When RabbitMQ confirms the cancellation, on_cancelok
        will be invoked by pika, which will then closing the channel and
        connection. The IOLoop is started again because this method is invoked
        when CTRL-C is pressed raising a KeyboardInterrupt exception. This
        exception stops the IOLoop which needs to be running for pika to
        communicate with RabbitMQ. All of the commands issued prior to starting
        the IOLoop will be buffered but not processed.

        """
        LOGGER.info('Stopping')
        self._closing = True
        self.stop_consuming()
        self._connection.ioloop.start()
        LOGGER.info('Stopped')


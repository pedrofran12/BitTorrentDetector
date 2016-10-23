import React, { Component } from 'react'
import { Table } from 'react-bootstrap'

import Packet from './Packet'

export default class PacketList extends Component {
  render() {
    return (
      <tbody>
      {
      this.props.pkts.map((pkt, i) => {
        return (
          <Packet
            key={i}
            date={pkt.date}
            ip={pkt.ip}
            mac={pkt.mac}
            host={pkt.host}
            hash={pkt.hash}
          />
        );
      })
      }
    </tbody>
    );
  }
}

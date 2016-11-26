import React, { Component } from 'react'
import { Table, Grid, Row} from 'react-bootstrap'

import io from 'socket.io-client'

import PacketList from './PacketList'

export default class App extends Component {
  constructor(props) {
    super(props);
    this.state = { pkts: []};
  }

  componentDidMount() {
    const context = this
    const socket = io()

    socket.on('data', packet => {
      context.setState({ pkts: [ packet, ...context.state.pkts]})
    })
  }

  render() {
    return (
      <Grid>
        <Row>
        <h1>Bit Torrent Trafic Detector</h1>
        <Table responsive>
          <thead>
            <tr>
              <th>Date</th>
              <th>Src IP</th>
              <th>Src MAC</th>
              <th>Host Name</th>
              <th>Torrent Hash</th>
              <th>Type of Detection</th>
            </tr>
          </thead>
          <PacketList
            pkts={this.state.pkts}
          />
        </Table>
        </Row>
      </Grid>
    );
  }
}

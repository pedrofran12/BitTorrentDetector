import React, { Component } from 'react'
import { Table } from 'react-bootstrap'

export default class Packet extends Component {
  render() {
    return (
      <tr key={this.props.index}>
        <td width="12%">{this.props.ip}</td>
        <td width="12%">{this.props.mac}</td>
        <td width="8%">{this.props.host}</td>
        <td width="25%">{this.props.hash}</td>
        <td width="25%">{this.props.description}</td>
        <td width="12%">{this.props.date}</td>
        <td width="6%">{this.props.detectiontype}</td>
      </tr>
    );
  }
}

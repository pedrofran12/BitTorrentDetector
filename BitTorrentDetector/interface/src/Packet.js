import React, { Component } from 'react'
import { Table } from 'react-bootstrap'

export default class Packet extends Component {
  render() {
    return (
      <tr key={this.props.index}>
        <td>{this.props.ip}</td>
        <td>{this.props.mac}</td>
        <td>{this.props.host}</td>
        <td>{this.props.hash}</td>
        <td>{this.props.date}</td>
      </tr>
    );
  }
}

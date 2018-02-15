import { createSocket, Socket, AddressInfo } from 'dgram'
import { decode, encode_response, RadiusPacket } from 'radius'
import Debug from 'debug'
import { authenticate } from './smtp-authenticator'
import { EventEmitter } from 'events';

const log = Debug('duplo:radius-server')

export interface RadiusServerOptions {
	secret: string
	port: number
	address: string
	domain: string
	smtp: {
		host: string
	}
}

export class RadiusAuthServer extends EventEmitter {
	socket: Socket

	constructor(private readonly options: RadiusServerOptions) {
		super()

		this.socket = createSocket({
			type: 'udp4',
			reuseAddr: true,
		})

		this.socket.on('message', (msg, rinfo) => {
			try {
				const packet = decode({ packet: msg, secret: this.options.secret })
				this.handlePacket(packet, rinfo).catch(error => this.emit('error', error))
			}
			catch (error) {
				log('error decoding radius packet', error)
				return
			}
		})
	}

	bind() {
		log(`binding to ${this.options.address}:${this.options.port}`)
		this.socket.bind(this.options.port, this.options.address)
		return this
	}

	private send(buffer: Buffer, address: AddressInfo) {
		return new Promise<number>(
			(resolve, reject) => this.socket.send(buffer, address.port, address.address,
				(error, bytes) => error ? reject(error) : resolve(bytes)
			)
		)
	}

	private sendEncodedResponse(code: string, packet: RadiusPacket, address: AddressInfo) {
		const encodedResponse = encode_response({
			code,
			secret: this.options.secret,
			packet: packet
		})
		return this.send(encodedResponse, address)
	}

	private async handleAccessRequestPacket(packet: RadiusPacket, remoteAddress: AddressInfo): Promise<void> {
		const username = packet.attributes['User-Name']
		const password = packet.attributes['User-Password']

		try {
			const authResponse = await authenticate(username, password, this.options.domain, this.options.smtp.host)
			if (authResponse.success) {
				log(`successfully authenticated radius client ${remoteAddress.address} :: ${username}`)
				this.emit('authenticated', { address: remoteAddress.address, username })
				await this.sendEncodedResponse('Access-Accept', packet, remoteAddress)
			}
		}
		catch (error) {
			log('error while handling access request', error)
			this.emit('rejected', { address: remoteAddress.address, username, message: error.message })
			await this.sendEncodedResponse('Access-Reject', packet, remoteAddress)
		}
	}

	private handlePacket(packet: RadiusPacket, remoteAddress: AddressInfo): Promise<void> {
		log(`handling ${packet.code} from ${remoteAddress.address}`)
		this.emit('packet', { address: remoteAddress.address, packet })
		switch (packet.code) {
			case 'Access-Request': return this.handleAccessRequestPacket(packet, remoteAddress)
		}

		return Promise.resolve()
	}
}
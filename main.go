package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"

	"image"
	"image/jpeg"
	_ "image/png"

	"github.com/gopxl/pixel/v2"
	"github.com/gopxl/pixel/v2/backends/opengl"
)

const (
	jpegHeader    = "/9j/4AAQSkZJRgABAgEBLAEsAAD/7QCcUGhvdG9zaG9wIDMuMAA4QklNBAQAAAAAAH8cAgUAFFNOQzczMDAgSlBFRyBFbmNvZGVyHAJzABJTTkM3MzAwIENJUyBNb2R1bGUcAlAAElNOQzczMDAgU0EyRFNQVEVBTRwCdAAXU09OSVguVEVDSE5PTE9HWS5DTy5MVEQcAngAF2h0dHA6Ly93d3cuc29uaXguY29tLnR3AP/+AQEwD/sGcAEAAHABAACAAQAACAEAAIABAAAcAgAAXgEAAF4BAAAcAgAAgAIAAIYBAAC8AQAA1AEAAAADAACGAQAAvAEAANQBAAAAAwAAKAIAAMwDAACIBQAAuAIAAEACAAAoAgAAoAIAACwDAAB0BgAAcA4AAFAFAADgAwAA9AIAAPQCAABkAwAA/AMAANQKAAAiCQAA7AQAAFAEAADwAwAAUAQAAKAFAAC+CwAAcgwAAAgHAAAQBQAAEAUAAEAGAAAQCwAA2g0AAEwIAAAMCAAAOAkAAGQPAACoFQAAEA4AAOQMAADaEwAARCAAANgXAABEIAAA2DgAANg4AABAgwD/wAARCAHgAoADASEAAhEBAxEB/9sAhAAVDhASEA0VEhESGBcVGSA2IyAdHSBCLzInNk5FUlFNRUtKVmF8aVZcdV1KS2yTbXWAhIuMi1NomKOXh6J8iIuFARcYGCAcID8jIz+FWUtZWYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYX/xAGiAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgsQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+gEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoLEQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2gAMAwEAAhEDEQA/AA=="
	jpegHeaderlen = 1024
)

func run() {
	frames := make(chan []byte, 100)
	go startReceiveVideoStream(frames)

	cfg := opengl.WindowConfig{
		Title:     "Double Camera Receiver",
		Bounds:    pixel.R(0, 0, 640, 480),
		VSync:     true,
		Resizable: true,
	}
	win, err := opengl.NewWindow(cfg)
	if err != nil {
		panic(err)
	}

	for frame := range frames {
		if win.Closed() {
			break
		}

		win.Clear(pixel.RGB(0, 0, 0))
		image, err := decodeFrame(frame)
		if err != nil {
			log.Printf("Decode failed: %v", err)
			continue
		}
		picture := pixel.PictureDataFromImage(image)
		sprite := pixel.NewSprite(picture, picture.Bounds())

		sprite.Draw(win, pixel.IM.Moved(win.Bounds().Center()))

		win.Update()
	}
}

func decodeFrame(frame []byte) (image.Image, error) {
	header := make([]byte, jpegHeaderlen)
	_, err := base64.StdEncoding.Decode(header, []byte(jpegHeader))
	if err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(header)
	_, err = buffer.Write(frame)
	if err != nil {
		return nil, err
	}

	image, err := jpeg.Decode(buffer)
	if err != nil {
		return nil, err
	}
	return image, nil
}

func main() {
	opengl.Run(run)
}

const (
	controlPort = 30863
	commandPort = 30864
	videoPort   = 30865
)

var serverIP = net.ParseIP("192.168.123.1")

func startReceiveVideoStream(c chan<- []byte) {
	defer close(c)
	log.Println("start listen on UDP video port")
	videoConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: videoPort,
	})
	if err != nil {
		log.Panicf("ListenUDP(videoPort) failed: %v", err)
	}
	defer videoConn.Close()

	log.Println("setting up control connection")
	controlConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   serverIP,
		Port: controlPort,
	})
	if err != nil {
		log.Panicf("DialUDP(controlPort) failed: %v", err)
	}
	defer controlConn.Close()

	log.Println("send video request packet")
	_, err = controlConn.Write([]byte("Bv"))
	if err != nil {
		log.Panicf("controlConn.Write failed: %v", err)
	}

	packetIndexOfFrame := 0
	frame := make([]byte, 0, 1024*32)
	for {
		packet, err := readVideoPacketFromUDP(videoConn)
		if err != nil {
			log.Panicf("startReceiveVideoStream: %v", err)
		}

		switch packet.marker {
		case videoPacketStart:
			if packetIndexOfFrame != packet.index {
				log.Printf("Unexpected start packet. Recover...")
			}
			frame = make([]byte, 0, 1024*32)
			frame = append(frame, packet.body...)
			packetIndexOfFrame++
		case videoPacketContinue:
			if packetIndexOfFrame != packet.index {
				log.Printf("Unexpected packet index. Reset index")
				packetIndexOfFrame = 0
				continue
			}
			frame = append(frame, packet.body...)
			packetIndexOfFrame++
		case videoPacketEnd:
			if packetIndexOfFrame != packet.index {
				log.Printf("Unexpected packet index. Reset index")
				packetIndexOfFrame = 0
				continue
			}
			frame = append(frame, packet.body...)
			packetIndexOfFrame = 0

			c <- frame
			frame = nil
		}
	}
}

var ErrReadPacketFailed = errors.New("invalid packet")

type videoPacketMarker int

const (
	videoPacketInvalid  = 0
	videoPacketStart    = 1
	videoPacketContinue = 2
	videoPacketEnd      = 3
)

type videoPacket struct {
	body   []byte
	index  int
	marker videoPacketMarker
}

func readVideoPacketFromUDP(conn *net.UDPConn) (videoPacket, error) {
	buf := make([]byte, 4096)
	n, addr, err := conn.ReadFromUDP(buf)

	if err != nil {
		return videoPacket{}, fmt.Errorf("readVideoPacketFromUDP: ReadFromUDP failed: %w", err)
	}
	if n != 1028 {
		return videoPacket{}, fmt.Errorf("readVideoPacketFromUDP: Packet size is unexpected: %d: %w", n, ErrReadPacketFailed)
	}
	if !addr.IP.Equal(serverIP) {
		return videoPacket{}, fmt.Errorf("readVideoPacketFromUDP: Ignoring packet from other server: %d: %w", n, ErrReadPacketFailed)
	}

	// 元の配列と切り離すためにコピーする。しなくていいと思うけれど
	body := make([]byte, 1024)
	copy(body, buf[:1024])

	// (marker) (marker) (length) (length)
	footer := buf[1024:1028]

	// 後ろ2オクテットがパケット番号らしい。ただ、256パケットもかかるフレームを見たことがないので、
	// footer[3] は参照しなくてもいいかもしれない。
	index := 256*int(footer[2]) + int(footer[3])

	var marker videoPacketMarker
	if bytes.Equal(footer[0:2], []byte{0xff, 0xda}) && index == 0 {
		marker = videoPacketStart
	} else if bytes.Equal(footer[0:2], []byte{0xff, 0xdd}) && index > 0 {
		marker = videoPacketContinue
	} else if bytes.Equal(footer[0:2], []byte{0x06, 0xd9}) {
		marker = videoPacketEnd
	} else {
		return videoPacket{}, fmt.Errorf("readVideoPacketFromUDP: Invalid marker: %v: %w", footer, ErrReadPacketFailed)
	}

	return videoPacket{
		body:   body,
		index:  index,
		marker: marker,
	}, nil
}

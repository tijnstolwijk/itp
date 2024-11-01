package main

import (
	"log"
	"os"
	"syscall"
  "net"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"

	"image"
	_ "image/jpeg"
	_ "image/png"


	"strconv"
  "fmt"
)

type Pixel struct {r int; g int; b int}
type Matrix [][]Pixel
func newMatrix(width int, height int) *Matrix {
  var m Matrix
  m = make([][]Pixel, height)
  for i := range m {
    m[i] = make([]Pixel, width)
  }
  return &m
}

func imgMatrix(img image.Image) *Matrix {
  width := img.Bounds().Max.X  
  height := img.Bounds().Max.Y 
  
  matrix := *newMatrix(width, height)
  for y := range img.Bounds().Max.Y {
    for x := range img.Bounds().Max.X {
      r, g, b, _ := img.At(x, y).RGBA()
      rInt := int(r >> 8)
      gInt := int(g >> 8)
      bInt := int(b >> 8)
      pixel := Pixel{r: rInt, b: bInt, g: gInt}
      matrix[y][x] = pixel
    }
  }
  return &matrix
}


func hexColors(pixel *Pixel) (bS, gS, rS string){
  bS = fmt.Sprintf("%x", pixel.b)
  if len(bS) == 1 {bS = "0" + bS} 
  gS = fmt.Sprintf("%x", pixel.g)
  if len(gS) == 1 {gS = "0" + gS} 
  rS = fmt.Sprintf("%x", pixel.r)
  if len(rS) == 1 {rS = "0" + rS} 
  return
}

func constructAddress(x, y int, b, g, r string) string {
  xS := fmt.Sprintf("%x", x)
  if len(xS) < 4 { for range 4 - len(xS) {xS = "0" + xS}}
  yS := fmt.Sprintf("%x", y)
  if len(yS) < 4 { for range 4 - len(yS) {yS = "0" + yS}}

  return fmt.Sprintf("2001:610:1908:a000:%s:%s:%s%s:%sff", xS, yS, b, g, r)
}
func precomputePackets(matrixPtr *Matrix, xZero, yZero int64) (buffers [][]byte, addresses []net.IP) {
  buffers = make([][]byte, 0)
  addresses = make([]net.IP, 0)
  matrix := *matrixPtr
  for y := range matrix {
    for x := range matrix[y] {
      pixel := matrix[y][x]
      b, g, r := hexColors(&pixel)
      
      srcAddr := net.ParseIP("fe80::1")
      dstAddrStr := constructAddress(int(xZero)+x, int(yZero)+y, b, g, r)
      dstAddr := net.ParseIP(dstAddrStr)
      addresses = append(addresses, dstAddr)

      log.Printf("Precomputed packet with address %s\n", dstAddrStr)
      ipv6 := &layers.IPv6{
        Version: 6,
        SrcIP: srcAddr,
        DstIP: dstAddr,
        HopLimit: 64,
        NextHeader: layers.IPProtocolICMPv6,
      }


      icmp := &layers.ICMPv6{
        TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
        Checksum: 0,
      }

      echo := &layers.ICMPv6Echo{
        Identifier: uint16(os.Getpid() & 0xffff),
        SeqNumber:  1,
      }
      
      buffer := gopacket.NewSerializeBuffer()
      options := gopacket.SerializeOptions{
        FixLengths:       true, 
        ComputeChecksums: false,
      }

      err := gopacket.SerializeLayers(buffer, options,
      ipv6,
      icmp,
      echo)
      if err != nil {
        log.Fatal("Error serializing to buffer: \n", err)
      }
      buffers = append(buffers, buffer.Bytes())
    }
  }
  return
}


func main() {
  inImg := os.Args[1:][0]
  raw, err := os.Open(inImg)
  if err != nil {
    log.Fatal("Error reading image, did you fuck it up?")
  }
  xZero, err := strconv.ParseInt(os.Args[1:][1], 0, 64)
  if err != nil {
    log.Fatal("Enter a number dumbass 0 to (1920 - image width)")
  }
  yZero, err := strconv.ParseInt(os.Args[1:][2], 0, 64)
  if err != nil {
    log.Fatal("Enter a number dumbass 0 to (1080 - image height)")
  }

  img, _, err := image.Decode(raw)
  if err != nil {
    log.Fatal("Error decoding image, did you fuck it up?")
  }
  log.Print("Image decoded")

  matrix := imgMatrix(img)
  log.Print("Matrix built")

  packets, _ := precomputePackets(matrix, xZero, yZero)

  sock, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
  if err != nil {
    log.Fatal("Error opening raw socket\n", err)
  }
  log.Print("Packet connection started")
  defer syscall.Close(sock)

  byteDst := net.ParseIP("2001:610:1908:a000::").To16()
  if byteDst == nil {
    log.Fatal("Incorrect ipv6?")
  }
  dstAddress := &syscall.SockaddrInet6{
    Addr: [16]byte{byteDst[0],byteDst[1],byteDst[2],byteDst[3],
                    byteDst[4],byteDst[5],byteDst[6],byteDst[7],
                    byteDst[8],byteDst[9],byteDst[10],byteDst[11],
                    byteDst[12],byteDst[13],byteDst[14],byteDst[15]},
  }

  for true{
    for _, packet := range packets {
      err := syscall.Sendto(sock, packet, 0, dstAddress)
      if err != nil {
        log.Fatal("Error sending a packet:\n", err)
      }
      log.Print("Sent a packet")
    }
  } 
}


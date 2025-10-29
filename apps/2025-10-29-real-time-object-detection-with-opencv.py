import cv2
import numpy as np
import torch
import torchvision.transforms as transforms
from torchvision.models.detection import fasterrcnn_resnet50_fpn
from PIL import Image
import threading
import queue
import tkinter as tk
from tkinter import messagebox

class ObjectDetectionApp:
    def __init__(self):
        self.model = fasterrcnn_resnet50_fpn(pretrained=True)
        self.model.eval()
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        
        self.coco_classes = [
            '__background__', 'person', 'bicycle', 'car', 'motorcycle', 'airplane', 'bus',
            'train', 'truck', 'boat', 'traffic light', 'fire hydrant', 'N/A', 'stop sign',
            'parking meter', 'bench', 'bird', 'cat', 'dog', 'horse', 'sheep', 'cow',
            'elephant', 'bear', 'zebra', 'giraffe', 'N/A', 'backpack', 'umbrella', 'N/A', 'N/A',
            'handbag', 'tie', 'suitcase', 'frisbee', 'skis', 'snowboard', 'sports ball',
            'kite', 'baseball bat', 'baseball glove', 'skateboard', 'surfboard', 'tennis racket',
            'bottle', 'N/A', 'wine glass', 'cup', 'fork', 'knife', 'spoon', 'bowl',
            'banana', 'apple', 'sandwich', 'orange', 'broccoli', 'carrot', 'hot dog', 'pizza',
            'donut', 'cake', 'chair', 'couch', 'potted plant', 'bed', 'N/A', 'dining table',
            'N/A', 'N/A', 'toilet', 'N/A', 'tv', 'laptop', 'mouse', 'remote', 'keyboard', 'cell phone',
            'microwave', 'oven', 'toaster', 'sink', 'refrigerator', 'N/A', 'book',
            'clock', 'vase', 'scissors', 'teddy bear', 'hair drier', 'toothbrush'
        ]

        self.transform = transforms.Compose([
            transforms.ToTensor()
        ])

        self.root = tk.Tk()
        self.root.title("Real-Time Object Detection")
        
        self.canvas = tk.Canvas(self.root, width=800, height=600)
        self.canvas.pack()

        self.start_button = tk.Button(self.root, text="Start Detection", command=self.start_detection)
        self.start_button.pack()

        self.stop_button = tk.Button(self.root, text="Stop Detection", command=self.stop_detection, state=tk.DISABLED)
        self.stop_button.pack()

        self.frame_queue = queue.Queue(maxsize=10)
        self.detection_thread = None
        self.is_running = False

    def preprocess_frame(self, frame):
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        pil_image = Image.fromarray(frame_rgb)
        input_tensor = self.transform(pil_image).unsqueeze(0)
        return input_tensor.to(self.device)

    def detect_objects(self, frame):
        with torch.no_grad():
            prediction = self.model(self.preprocess_frame(frame))[0]
        
        boxes = prediction['boxes'].cpu().numpy()
        labels = prediction['labels'].cpu().numpy()
        scores = prediction['scores'].cpu().numpy()
        
        return boxes, labels, scores

    def draw_detections(self, frame, boxes, labels, scores, threshold=0.5):
        for box, label, score in zip(boxes, labels, scores):
            if score > threshold:
                x1, y1, x2, y2 = map(int, box)
                class_name = self.coco_classes[label]
                cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)
                cv2.putText(frame, f'{class_name}: {score:.2f}', (x1, y1-10), 
                            cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
        return frame

    def detection_loop(self):
        cap = cv2.VideoCapture(0)
        while self.is_running:
            ret, frame = cap.read()
            if not ret:
                break

            boxes, labels, scores = self.detect_objects(frame)
            frame_with_detections = self.draw_detections(frame, boxes, labels, scores)
            
            try:
                self.frame_queue.put_nowait(frame_with_detections)
            except queue.Full:
                pass

        cap.release()

    def update_canvas(self):
        try:
            frame = self.frame_queue.get_nowait()
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            photo = tk.PhotoImage(data=cv2.imencode('.png', frame_rgb)[1].tobytes())
            self.canvas.create_image(0, 0, anchor=tk.NW, image=photo)
            self.canvas.image = photo
        except queue.Empty:
            pass
        
        if self.is_running:
            self.root.after(30, self.update_canvas)

    def start_detection(self):
        if not self.is_running:
            self.is_running = True
            self.detection_thread = threading.Thread(target=self.detection_loop)
            self.detection_thread.start()
            self.update_canvas()
            
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

    def stop_detection(self):
        if self.is_running:
            self.is_running = False
            if self.detection_thread:
                self.detection_thread.join()
            
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def run(self):
        self.root.mainloop()

def main():
    app = ObjectDetectionApp()
    app.run()

if __name__ == "__main__":
    main()
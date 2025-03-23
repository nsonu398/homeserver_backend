const fs = require('fs');
const tf = require('@tensorflow/tfjs-node');
const tesseract = require("node-tesseract-ocr");
const https = require('https');

// Path to test image
const TEST_IMAGE_PATH = '9b201e38-0732-40ee-b666-da0110e63dc9.jpg';

// Function to download ImageNet classes
function downloadImageNetClasses() {
  return new Promise((resolve, reject) => {
    const url = 'https://storage.googleapis.com/download.tensorflow.org/data/imagenet_class_index.json';
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          const classesObj = JSON.parse(data);
          // Convert from {0: ["n01440764", "tench"], 1: [...]} format to array of class names
          const classes = Object.values(classesObj).map(arr => arr[1]);
          fs.writeFileSync('imagenet_classes.json', JSON.stringify(classes));
          resolve(classes);
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', (err) => {
      reject(err);
    });
  });
}

async function loadImageNetClasses() {
  try {
    if (fs.existsSync('imagenet_classes.json')) {
      return JSON.parse(fs.readFileSync('imagenet_classes.json', 'utf8'));
    } else {
      return await downloadImageNetClasses();
    }
  } catch (error) {
    console.error('Error loading ImageNet classes:', error);
    throw error;
  }
}

async function extractTextFromImage(imagePath) {
  console.log(`Starting OCR text extraction for ${imagePath}...`);

  const config = {
    lang: "eng",
    oem: 3,
    psm: 3,
  }
  
  try {
    const text = await tesseract.recognize(imagePath, config);
    console.log(`OCR complete. Found ${text.length} characters of text`);
    return text;
  } catch (error) {
    console.error('Error in OCR processing:', error);
    throw error;
  }
}

async function generateImageTags(imagePath) {
  console.log(`Starting image classification for ${imagePath}...`);
  
  try {
    // Load the MobileNet model
    const model = await tf.loadGraphModel(
      'https://tfhub.dev/google/tfjs-model/imagenet/mobilenet_v2_100_224/classification/3/default/1',
      { fromTFHub: true }
    );
    
    console.log('Model loaded, preparing image...');
    
    // Read and prepare the image
    const imageBuffer = fs.readFileSync(imagePath);
    const tfImage = tf.node.decodeImage(imageBuffer);
    
    // Resize the image to match what the model expects
    const resizedImg = tf.image.resizeBilinear(tfImage, [224, 224]);
    
    // Expand and normalize the image
    const expandedImg = resizedImg.expandDims(0);
    const normalizedImg = expandedImg.toFloat().div(tf.scalar(127)).sub(tf.scalar(1));
    
    // Run inference
    console.log('Running model inference...');
    const predictions = await model.predict(normalizedImg).data();
    
    // Get the ImageNet class names
    const classNames = await loadImageNetClasses();
    
    // Get top 5 predictions
    const topPredictions = Array.from(predictions)
      .map((probability, index) => {
        return {
          class: classNames[index] || `unknown_${index}`,
          probability: probability
        };
      })
      .sort((a, b) => b.probability - a.probability)
      .slice(0, 5);
    
    console.log('Classification complete. Top 5 tags:');
    topPredictions.forEach(p => {
      console.log(`- ${p.class} (${Math.round(p.probability * 100)}%)`);
    });
    
    // Extract tags from predictions
    const tags = topPredictions.map(p => p.class);
    
    // Cleanup tensors
    tf.dispose([tfImage, resizedImg, expandedImg, normalizedImg]);
    
    return tags;
  } catch (error) {
    console.error('Error in image classification:', error);
    throw error;
  }
}

async function testImageAnalysis() {
  console.log('=== Starting Image Analysis Test ===');
  console.log(`Testing with image: ${TEST_IMAGE_PATH}`);
  
  try {
    // Check if the file exists
    if (!fs.existsSync(TEST_IMAGE_PATH)) {
      throw new Error(`Test image not found at ${TEST_IMAGE_PATH}`);
    }
    
    // Extract text
    console.log('\n--- Text Extraction ---');
    const extractedText = await extractTextFromImage(TEST_IMAGE_PATH);
    console.log('\nExtracted Text:');
    console.log(extractedText || '(No text found)');
    
    // Generate tags
    console.log('\n--- Image Classification ---');
    const tags = await generateImageTags(TEST_IMAGE_PATH);
    console.log('\nGenerated Tags:');
    console.log(tags.join(', '));
    
    console.log('\n=== Test Complete ===');
    return {
      extractedText,
      tags
    };
  } catch (error) {
    console.error('Test failed:', error);
  }
}

// Run the test
testImageAnalysis();
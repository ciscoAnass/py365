import os
import tempfile
import streamlit as st
from langchain.document_loaders import PyPDFLoader, TextLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import Chroma
from langchain.llms import HuggingFacePipeline
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
from langchain.chains import RetrievalQA

class DocumentQASystem:
    def __init__(self):
        st.set_page_config(page_title="Document Q&A", page_icon="📄")
        self.vector_store = None
        self.qa_chain = None
        self.embeddings = None
        self.llm = None
        self.initialize_components()

    def initialize_components(self):
        try:
            self.embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
            model_name = "facebook/opt-125m"
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForCausalLM.from_pretrained(model_name)
            
            text_generation_pipeline = pipeline(
                "text-generation", 
                model=model, 
                tokenizer=tokenizer,
                max_length=512
            )
            
            self.llm = HuggingFacePipeline(pipeline=text_generation_pipeline)
        except Exception as e:
            st.error(f"Error initializing components: {e}")

    def load_documents(self, uploaded_files):
        documents = []
        for uploaded_file in uploaded_files:
            with tempfile.NamedTemporaryFile(delete=False, suffix=uploaded_file.name.split('.')[-1]) as temp_file:
                temp_file.write(uploaded_file.getvalue())
                temp_file_path = temp_file.name

            try:
                if uploaded_file.name.endswith('.pdf'):
                    loader = PyPDFLoader(temp_file_path)
                else:
                    loader = TextLoader(temp_file_path)
                
                docs = loader.load()
                documents.extend(docs)
            except Exception as e:
                st.error(f"Error loading {uploaded_file.name}: {e}")
            
            os.unlink(temp_file_path)

        return documents

    def process_documents(self, documents):
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
        texts = text_splitter.split_documents(documents)
        
        self.vector_store = Chroma.from_documents(
            documents=texts, 
            embedding=self.embeddings
        )

        self.qa_chain = RetrievalQA.from_chain_type(
            llm=self.llm,
            chain_type="stuff",
            retriever=self.vector_store.as_retriever(search_kwargs={"k": 3})
        )

    def render_ui(self):
        st.title("📄 Document Q&A System")
        
        uploaded_files = st.file_uploader(
            "Upload Documents", 
            type=['pdf', 'txt'], 
            accept_multiple_files=True
        )

        if uploaded_files:
            with st.spinner('Processing documents...'):
                documents = self.load_documents(uploaded_files)
                self.process_documents(documents)
                st.success(f"Processed {len(documents)} documents")

        query = st.text_input("Ask a question about your documents")

        if query and self.qa_chain:
            with st.spinner('Generating response...'):
                try:
                    result = self.qa_chain({"query": query})
                    st.write("### Answer")
                    st.write(result['result'])
                except Exception as e:
                    st.error(f"Error generating response: {e}")

    def run(self):
        self.render_ui()

def main():
    app = DocumentQASystem()
    app.run()

if __name__ == "__main__":
    main()
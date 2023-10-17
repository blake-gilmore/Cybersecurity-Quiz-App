import React from 'react'
export default function InputBox(props){
    return(
        <label>
            {props.label} - {props.numQuestions} Questions:&emsp;
            <input 
                className="w-12 border-2 border-slate-400 font-normal"
                type='text' 
                onChange={e=>props.onChange(e.target.value, props.id)}
            />
            <p className="text-red-600">{props.inputResponse}</p>
        </label>
    )
}
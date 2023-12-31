import React, {useState} from 'react'
import InputBox from './inputBox';
import { isValidNumber} from '../library/functions';
import questionDatabase from '../data/data';


export default function QuestionSelections(props){
    const [tempNum, setTempNum]=useState(questionDatabase.map((section) => ({key: section.id, id: section.id, value: 0, inputResponse: '', questions: section.sectionContent.length})));
    const [validNums, setValidNums] = useState([]);

    function getData(val, idIn){
        setTempNum(
            tempNum.map((num) =>
                num.id === idIn
                    ? { ...num, value: val }
                    : { ...num }
            )
        );
    }

    function handleFormSubmit(){
        var boolArr = tempNum.map((num) => isValidNumber(num.value, num.questions))
        var canContinue = true;

        for (let i = 0; i < boolArr.length; i++){
            if (!boolArr[i]){
                tempNum[i].inputResponse = " Invalid number of questions for this section.";
                canContinue = false;
            }
            else
                tempNum[i].inputResponse = "";
        }
        setValidNums(boolArr);
        

        if (canContinue){
            props.handleQuestions(tempNum);
        }
    }

    return(
        <div className='container w-fit'>
            <div className="text-right">
                {questionDatabase.map((section) => (
                    <div className='font-bold text-lg' key = {section.id}>
                        <InputBox 
                            key = {section.id}
                            label = {section.sectionTitle}
                            numQuestions = {section.sectionContent.length}
                            sectionContent = {section.sectionContent}
                            onChange = {getData}
                            id = {section.id}
                            inputResponse = {tempNum[section.id-1].inputResponse}
                        />
                        <br/>
                    </div>
                ))}
                <br/>
            </div>

            <button className="tracking-wider p-2.5 border-2 border-gray-400 rounded-lg bg-gray-200"onClick={()=>handleFormSubmit()}>Submit</button>
        </div>
    )
}